"""開発環境から PHP のバージョンを自動で拾う。

どれも「調べるだけ」で、見つけた環境の設定やファイルは変更しない。
外部コマンドの実行は run 引数で差し替えられる(テスト用)。
"""

import glob
import ipaddress
import os
import re
import shutil
import socket
import string
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

VERSION_CMD = ["-n", "-r", "echo PHP_VERSION;"]  # -n: php.ini を読まない(拡張の読み込みエラーを避ける)
RUN_TIMEOUT_SEC = 10
MAX_CONTAINERS = 20
_PHP_IN_HEADER_RE = re.compile(r"PHP/(\d+\.\d+\.\d+\S*)", re.IGNORECASE)

KIND_LOCAL = "このPC"
KIND_DOCKER = "Docker"
KIND_URL = "開発用サイト"


@dataclass
class Finding:
    kind: str       # KIND_*
    place: str      # 見つけた場所(パス・コンテナ名・URL)
    version: str    # "8.3.12" "8.3.6-1ubuntu…" 等。PHP_VERSION そのまま


def _run(args, timeout=RUN_TIMEOUT_SEC):
    """コマンドを実行して標準出力を返す。失敗したら None。"""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # exe から呼んでも黒い窓を出さない
    try:
        # stdin=DEVNULL: 窓だけのexe(--windowed)には標準入力が無く、指定しないと失敗することがある
        cp = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                            creationflags=flags, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    if cp.returncode != 0:
        return None
    return cp.stdout.strip()


# --- このPC ---

def _drives():
    return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]


def local_candidates():
    """php.exe がありそうな場所を列挙する(存在するものだけ。重複なし)。"""
    patterns = []
    for drive in _drives():
        patterns += [
            drive + r"xampp\php\php.exe",
            drive + r"laragon\bin\php\*\php.exe",
            drive + r"wamp64\bin\php\*\php.exe",
            drive + r"wamp\bin\php\*\php.exe",
            drive + r"MAMP\bin\php\*\php.exe",
            drive + r"php*\php.exe",
            drive + r"tools\php*\php.exe",
            drive + r"Program Files\PHP\*\php.exe",
            drive + r"Program Files\PHP\php.exe",
        ]
    home = os.path.expanduser("~")
    patterns += [
        os.path.join(home, r"scoop\apps\php*\current\php.exe"),
        os.path.join(home, r"AppData\Local\Programs\Local\resources\extraResources\lightning-services"
                           r"\php-*\bin\win64\php.exe"),
    ]
    found = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory:
            patterns.append(os.path.join(directory, "php.exe"))
    seen = set()
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            key = os.path.normcase(os.path.realpath(path))
            if key not in seen and os.path.isfile(path):
                seen.add(key)
                found.append(path)
    return found


def find_local(run=_run, candidates=None):
    candidates = local_candidates() if candidates is None else candidates
    results = []
    for path in candidates:
        out = run([path] + VERSION_CMD)
        if out:
            results.append(Finding(KIND_LOCAL, path, out.splitlines()[-1].strip()))
    return results


# --- Docker ---

def find_docker(run=_run):
    """動いているコンテナで PHP_VERSION を表示させる。Docker が無ければ空。"""
    if run is _run and not shutil.which("docker"):
        return []
    listing = run(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])
    if not listing:
        return []
    results = []
    for line in listing.splitlines()[:MAX_CONTAINERS]:
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        cid, name, image = parts
        out = run(["docker", "exec", cid, "php"] + VERSION_CMD)
        if out:
            results.append(Finding(KIND_DOCKER, f"{name}({image})", out.splitlines()[-1].strip()))
    return results


# --- 開発用サイトのURL ---

class UrlNotAllowed(ValueError):
    pass


def _host_is_local(host, resolve=socket.getaddrinfo):
    """名前解決した全アドレスが、自分のPC(ループバック)か社内LAN(プライベート)なら True。"""
    try:
        infos = resolve(host, None)
    except OSError:
        raise UrlNotAllowed(f"「{host}」が見つかりません")
    addrs = {info[4][0].split("%")[0] for info in infos}
    return bool(addrs) and all(
        (ip.is_loopback or ip.is_private) and not ip.is_link_local
        for ip in map(ipaddress.ip_address, addrs))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # 転送先(外部サイトかもしれない)には付いていかない
        return None


def check_url(url, resolve=socket.getaddrinfo, opener=None):
    """開発用サイトの応答ヘッダから PHP の版を読む。

    他人のサイトを調べる道具にしないため、自分のPC・社内LANのアドレスだけ受け付ける。
    版が分からなければ UrlNotAllowed 以外の ValueError を投げる。
    """
    if "://" not in url:
        url = "http://" + url
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UrlNotAllowed("http:// または https:// で始まるアドレスを入れてください")
    if not _host_is_local(parts.hostname, resolve):
        raise UrlNotAllowed("このPC(localhost)や社内LANのアドレスだけ調べられます。"
                            "公開中のサイトは調べられません")
    # ProxyHandler({}): 社内プロキシ経由にせず直接つなぐ
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "web-shindan"})
    try:
        res = opener.open(req, timeout=RUN_TIMEOUT_SEC)
        headers = res.headers
        res.close()
    except urllib.error.HTTPError as e:  # 404・転送(3xx)でもヘッダは読める
        headers = e.headers
    except (OSError, ValueError) as e:
        raise ValueError(f"サイトにつながりませんでした({type(e).__name__})")
    for name in ("X-Powered-By", "Server"):
        m = _PHP_IN_HEADER_RE.search(headers.get(name, "") or "")
        if m:
            return Finding(KIND_URL, url, m.group(1))
    raise ValueError("サイトがPHPのバージョンを表示していませんでした"
                     "(セキュリティのため隠している設定はよくあります)")
