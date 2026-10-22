"""開発フォルダの中で、秘密の鍵(APIキー・パスワード)が漏れそうな置き方をしていないかを調べる。

ファイルの中身はこのPCの中で読むだけで、外には送らない。見つけた鍵は先頭だけ残して伏せ字にし、全体は持たない。
探すのは「形でわかる鍵」(sk_live_… 等)だけ。どんな秘密でも見つけられるわけではない。
"""

import base64
import json
import os
import re
from dataclasses import dataclass

from . import core, detect, scanners

MAX_FILE_BYTES = 512 * 1024
TEXT_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html", ".htm", ".php",
             ".py", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".json", ".yml", ".yaml", ".toml", ".ini", ".conf",
             ".cfg", ".xml", ".properties", ".sh", ".bat", ".ps1", ".txt", ".md", ".sql"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock", "uv.lock",
              "Pipfile.lock", "Gemfile.lock", "Cargo.lock", "go.sum"}
# 見本のファイル(.env.example 等)は、本物の鍵が入っていない前提で飛ばす
SAMPLE_RE = re.compile(r"\.(example|sample|template|dist)$|\.(example|sample)\.", re.I)
PUBLIC_DIRS = {"public", "static", "www", "htdocs", "public_html", "assets"}
# ブラウザに配られる環境変数の頭(Next.js・Vite・Create React App・Nuxt・SvelteKit/Astro・Expo・Gatsby)
PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_", "EXPO_PUBLIC_", "GATSBY_")
SECRET_NAME_RE = re.compile(r"SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD", re.I)
PLACEHOLDER_RE = re.compile(r"x{4,}|your|example|dummy|sample|changeme|placeholder|<|\.\.\.|\*{3,}", re.I)

# (名前, 正規表現, 秘密か)。秘密でないもの(ブラウザに置く前提の鍵)は「制限をかけて」の要確認にする
KEY_RULES = [
    ("秘密鍵(PRIVATE KEY)", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), True),
    ("AWS のアクセスキー", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    ("Anthropic の APIキー", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), True),
    ("OpenAI の APIキー", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"), True),
    ("Stripe の秘密キー(本番)", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"), True),
    ("GitHub のトークン", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"), True),
    ("Slack のトークン", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), True),
    ("SendGrid の APIキー", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), True),
    ("Google の APIキー", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), False),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}")
ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([^'\"#\s]*)")


@dataclass
class Leak:
    kind: str        # 鍵の種類
    file: str        # 開発フォルダからの相対パス
    line: int
    masked: str      # 先頭だけ残した伏せ字
    level: str       # core.DANGER / core.CHECK
    reason: str


def mask(value):
    return f"{value[:6]}…({len(value)}文字)" if len(value) > 6 else "…"


def _jwt_role(token_payload):
    try:
        raw = base64.urlsafe_b64decode(token_payload + "=" * (-len(token_payload) % 4))
        return str(json.loads(raw).get("role", ""))
    except (ValueError, AttributeError):
        return ""


def find_keys(text):
    """[(行番号, 種類, 値, 秘密か)]。見本の値(xxxx・your… 等)は飛ばす。"""
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:  # 圧縮された1行のファイル等は、行ごと見るのをやめる
            line = line[:5000]
        for name, rx, secret in KEY_RULES:
            for m in rx.finditer(line):
                if not PLACEHOLDER_RE.search(m.group(0)):
                    out.append((no, name, m.group(0), secret))
        for m in JWT_RE.finditer(line):
            if _jwt_role(m.group(1)) == "service_role":  # Supabase の全権限の鍵(anon の鍵はブラウザに置いてよい)
                out.append((no, "Supabase の service_role キー", m.group(0), True))
    return out


def _is_env_file(name):
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


class _Git:
    """git で「記録されているか」「無視する設定か」を見る(調べるだけ。何も変更しない)。"""

    def __init__(self, root):
        self.top = detect._run(["git", "-C", root, "rev-parse", "--show-toplevel"])
        self.root = root

    def tracked(self, path):
        return bool(self.top and detect._run(["git", "-C", self.root, "ls-files", "--", path]))

    def ignored(self, path):
        if not self.top:
            return None
        out = detect._run(["git", "-C", self.root, "ls-files", "--others", "--ignored", "--exclude-standard", "--",
                           path])
        return None if out is None else bool(out)


def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.relpath(dirpath, root).count(os.sep) + (dirpath != root)
        dirnames[:] = [] if depth >= scanners.MAX_DEPTH else sorted(
            d for d in dirnames if d not in scanners.SKIP_DIRS and not d.startswith(".")
            and d not in ("wp-includes", "wp-admin", "wp-content"))
        for name in sorted(filenames):
            yield dirpath, name


def scan(root, git=None):
    """[Leak] を返す。git: テスト用に差し替えられる(_Git と同じ形)。"""
    root = os.path.abspath(root)
    git = git or _Git(root)
    leaks = []
    for dirpath, name in _walk(root):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        env = _is_env_file(name)
        if name in SKIP_FILES or SAMPLE_RE.search(name):
            continue
        if not env and os.path.splitext(name)[1].lower() not in TEXT_EXTS:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if env:
            leaks += _check_env_file(rel, path, text, git)
        else:
            leaks += _check_source(rel, text)
    return sorted(leaks, key=lambda x: (x.level != core.DANGER, x.file, x.line))


def _check_env_file(rel, path, text, git):
    out = []
    has_secret = False
    for no, line in enumerate(text.splitlines(), 1):
        m = ENV_LINE_RE.match(line)
        if not m or not m.group(2) or PLACEHOLDER_RE.search(m.group(2)):
            continue
        name, value = m.group(1), m.group(2)
        keys = find_keys(line)
        secret_key = next(((k, v) for _, k, v, s in keys if s), None)
        has_secret = has_secret or bool(keys) or bool(SECRET_NAME_RE.search(name))
        if name.upper().startswith(PUBLIC_PREFIXES) and (secret_key or SECRET_NAME_RE.search(name)):
            kind = secret_key[0] if secret_key else f"秘密らしい値({name})"
            out.append(Leak(kind, rel, no, mask(value), core.DANGER,
                            f"{name} は名前の頭が「{name.split('_')[0]}_」なので、ブラウザに配られて誰でも見られます。"
                            "秘密の値はこの頭を付けずに、サーバー側だけで使ってください"))
    if git.tracked(path):
        out.insert(0, Leak("環境変数ファイル", rel, 0, "", core.DANGER,
                           "git に記録されています。GitHub 等に上げていれば、中の鍵は漏れたものとして扱い、"
                           "作り直してください(記録から消すだけでは過去の履歴に残ります)"))
    elif has_secret and git.ignored(path) is False:
        out.insert(0, Leak("環境変数ファイル", rel, 0, "", core.CHECK,
                           ".gitignore で無視する設定になっていないため、次に git で記録すると一緒に上がってしまいます。"
                           ".gitignore に追加してください"))
    return out


def _check_source(rel, text):
    out = []
    public = any(p.lower() in PUBLIC_DIRS for p in rel.split(os.sep)[:-1])
    for no, kind, value, secret in find_keys(text):
        if secret:
            where = "公開されるフォルダ" if public else "プログラム"
            out.append(Leak(kind, rel, no, mask(value), core.DANGER,
                            f"{where}に直接書かれています。GitHub や公開中のサイトから見られるおそれがあります。"
                            "環境変数(.env)に移し、すでに公開していたなら鍵を作り直してください"))
        else:
            out.append(Leak(kind, rel, no, mask(value), core.CHECK,
                            "ブラウザに置く前提の鍵ですが、使えるサイト(リファラー)や API を制限していないと"
                            "他人に使われて料金がかかることがあります。Google Cloud の画面で制限を確認してください"))
    return out
