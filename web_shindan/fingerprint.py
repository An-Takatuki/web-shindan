"""サイトのURLを1回開いて、何で動いているか・どこに置いてあるかを推定する。

ブラウザで1回開くのと同じことしかしない(リンクをたどらない・別のパスを試さない・攻撃のような送信をしない)。
"""

import datetime
import http.client
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import APP_VERSION

TIMEOUT_SEC = 15
MAX_BODY = 1024 * 1024
MAX_REDIRECTS = 3
USER_AGENT = f"Mozilla/5.0 (compatible; WebShindan/{APP_VERSION}; self-check)"

# 置き場所の種類
HOST_BUILDER = "builder"   # サイト作成サービス。中身の更新はすべてサービス側
HOST_STATIC = "static"     # 静的ホスティング。サーバーの更新はサービス側、部品はあなた
HOST_PAAS = "paas"         # アプリ実行サービス。OS等はサービス側、部品と実行環境の版はあなた
HOST_CDN = "cdn"           # 手前の配信網だけ見えている。後ろは不明
HOST_SELF = "self"         # 自分で管理するサーバー(VPS・レンタルサーバー等)の可能性

HOSTING_NOTES = {
    HOST_BUILDER: "サイト作成サービスです。サーバーや部品の更新はサービス側が行うので、"
                  "あなたが気にするのは追加したアプリ・プラグインとログインの管理くらいです。",
    HOST_STATIC: "サーバー本体の更新はサービス側が行います。あなたが気にするのは、サイトを作るのに使った部品です。",
    HOST_PAAS: "サーバーのOSなどはサービス側が更新します。サイトの部品と、Node.js・PHP・Pythonなどの版の指定は"
               "あなたの担当です。",
    HOST_CDN: "手前の配信サービスしか見えないため、その後ろでサイトがどこに置かれているかはわかりません。",
    HOST_SELF: "自分で管理するサーバー(VPS・クラウド)かレンタルサーバーのようです。VPSやクラウドの場合は、"
               "サーバーの中(OS・Webサーバー・PHPやNode.jsの本体)の更新もあなたの担当です。",
}


@dataclass
class Tech:
    name: str
    version: str | None
    evidence: str


@dataclass
class Hosting:
    name: str
    kind: str
    evidence: str


@dataclass
class SiteInfo:
    url: str                                   # 最後に開いたURL
    status: int
    techs: list = field(default_factory=list)
    hostings: list = field(default_factory=list)
    exposed_versions: list = field(default_factory=list)  # ヘッダで版を公開しているもの
    cert_expires: datetime.date | None = None  # HTTPS の証明書の期限(取れた時だけ)
    advice: list = field(default_factory=list)  # あると安心な設定で、無いもの [(名前, 説明)]

    @property
    def https(self):
        return self.url.lower().startswith("https://")

    def tech(self, name):
        return next((t for t in self.techs if t.name == name), None)

    @property
    def uses_php(self):
        return any(t.name in PHP_TECHS for t in self.techs)

    @property
    def php_version(self):
        t = self.tech("PHP")
        return t.version if t else None


PHP_TECHS = {"PHP", "WordPress", "Laravel", "EC-CUBE", "Drupal", "Joomla", "Movable Type"}
NON_PHP_TECHS = {"Next.js", "Nuxt", "Gatsby", "Astro", "SvelteKit", "Remix", "Express", "ASP.NET", "Django",
                 "Ruby on Rails", "Streamlit", "Angular"}

# (名前, ヘッダ名 or None, 正規表現, 版を取るグループ番号 or None)。ヘッダ名 None は HTML を見る
TECH_RULES = [
    ("PHP", "x-powered-by", r"PHP/?(\d+\.\d+\.\d+\S*)?", 1),
    ("PHP", "set-cookie", r"\bPHPSESSID=", None),
    ("WordPress", None, r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ?([\d.]+)?', 1),
    ("WordPress", None, r"/wp-(?:content|includes)/", None),
    ("WordPress", "link", r"api\.w\.org", None),
    ("Laravel", "set-cookie", r"\blaravel_session=", None),
    # 本文に「EC-CUBE」と書いてあるだけのサイトを誤判定しないよう、EC-CUBE 固有のファイルの置き場所で見る
    ("EC-CUBE", None, r"/html/template/[\w-]+/assets/|/user_data/packages/", None),
    ("EC-CUBE", "set-cookie", r"\beccube(?:session)?=", None),
    ("Drupal", None, r'<meta[^>]+content=["\']Drupal ?(\d+)?', 1),
    ("Drupal", "x-generator", r"Drupal ?(\d+)?", 1),
    ("Joomla", None, r'<meta[^>]+content=["\']Joomla!? ?([\d.]+)?', 1),
    ("Movable Type", None, r'<meta[^>]+content=["\']Movable Type(?: Pro)? ?([\d.]+)?', 1),
    ("Next.js", "x-powered-by", r"Next\.js", None),
    ("Next.js", "x-nextjs-cache", r".", None),
    ("Next.js", "x-nextjs-prerender", r".", None),
    ("Next.js", None, r"/_next/static/", None),
    ("Nuxt", None, r"__NUXT__|/_nuxt/", None),
    ("Gatsby", None, r'<meta[^>]+content=["\']Gatsby ?([\d.]+)?', 1),
    ("Astro", None, r'<meta[^>]+content=["\']Astro v?([\d.]+)?', 1),
    ("SvelteKit", None, r"__sveltekit_", None),
    ("Remix", None, r"__remixContext", None),
    ("Angular", None, r'ng-version=["\']([\d.]+)', 1),
    ("Express", "x-powered-by", r"^Express$", None),
    ("ASP.NET", "x-powered-by", r"ASP\.NET", None),
    ("ASP.NET", "x-aspnet-version", r"([\d.]+)", 1),
    ("Django", "set-cookie", r"\bcsrftoken=", None),
    ("Ruby on Rails", "x-runtime", r"^[\d.]+$", None),
    ("Streamlit", None, r"<title>Streamlit</title>", None),
]

# (名前, 種類, ヘッダ名 or None, 正規表現)。上から順に判定し、同じ名前は1回だけ
HOSTING_RULES = [
    ("Wix", HOST_BUILDER, "x-wix-request-id", r"."),
    ("Shopify", HOST_BUILDER, "x-shopid", r"."),
    ("Squarespace", HOST_BUILDER, "server", r"(?i)squarespace"),
    ("STUDIO", HOST_BUILDER, None, r"studio\.design|storage\.googleapis\.com/studio-"),
    ("Jimdo", HOST_BUILDER, None, r"jimdo(?:cdn)?\.com"),
    ("Vercel", HOST_PAAS, "x-vercel-id", r"."),
    ("Vercel", HOST_PAAS, "server", r"(?i)^vercel$"),
    ("Netlify", HOST_STATIC, "x-nf-request-id", r"."),
    ("Netlify", HOST_STATIC, "server", r"(?i)^netlify"),
    ("GitHub Pages", HOST_STATIC, "server", r"(?i)^GitHub\.com$"),
    ("Cloudflare Pages", HOST_STATIC, "x-cf-pages", r"."),
    ("Firebase Hosting", HOST_STATIC, "x-firebase-hosting", r"."),
    ("Render", HOST_PAAS, "x-render-origin-server", r"."),
    ("Fly.io", HOST_PAAS, "fly-request-id", r"."),
    ("Heroku", HOST_PAAS, "via", r"(?i)vegur"),
    ("Google Cloud", HOST_PAAS, "server", r"(?i)Google Frontend"),
    ("AWS CloudFront", HOST_CDN, "x-amz-cf-id", r"."),
    ("Cloudflare", HOST_CDN, "cf-ray", r"."),
    ("Fastly", HOST_CDN, "x-served-by", r"(?i)cache-"),
    ("nginx", HOST_SELF, "server", r"(?i)^nginx"),
    ("Apache", HOST_SELF, "server", r"(?i)^Apache"),
    ("LiteSpeed", HOST_SELF, "server", r"(?i)LiteSpeed"),
    ("Caddy", HOST_SELF, "server", r"(?i)^Caddy"),
    ("Caddy", HOST_SELF, "via", r"(?i)Caddy"),
    ("Microsoft IIS", HOST_SELF, "server", r"(?i)Microsoft-IIS"),
]

_SERVER_VERSION_RE = re.compile(r"(nginx|Apache|Microsoft-IIS|LiteSpeed|PHP|OpenSSL)/(\d+(?:\.\d+)+)", re.I)


class UrlNotAllowed(ValueError):
    pass


def _check_host(host, resolve=socket.getaddrinfo):
    """リンクローカル(169.254.x.x=クラウドの内部情報の窓口)等、調べてはいけない宛先を断る。"""
    try:
        infos = resolve(host, None)
    except OSError:
        raise UrlNotAllowed(f"「{host}」が見つかりません。URLが合っているか確認してください")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise UrlNotAllowed("このアドレスは調べられません")


def normalize_url(url):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UrlNotAllowed("https:// で始まるサイトのアドレスを入れてください")
    return url


def _same_site(a, b):
    strip = lambda h: (h or "").lower().removeprefix("www.")  # noqa: E731
    return strip(urllib.parse.urlsplit(a).hostname) == strip(urllib.parse.urlsplit(b).hostname)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # 転送は自分で1回ずつ確かめてから追う


class _CertHTTPSHandler(urllib.request.HTTPSHandler):
    """ページを開いたのと同じ接続から、証明書(期限を見るため)を受け取る。追加の接続はしない。"""

    def __init__(self, tls):
        super().__init__()
        self.tls = tls

    def https_open(self, req):
        tls = self.tls

        class Conn(http.client.HTTPSConnection):
            def connect(self):
                super().connect()
                tls["cert"] = self.sock.getpeercert()

        return self.do_open(Conn, req, context=self._context)


def fetch(url, resolve=socket.getaddrinfo, opener=None, tls=None):
    """(最後のURL, 状態コード, ヘッダ(小文字キーの辞書, 複数値は改行で連結), HTML) を返す。

    tls: 辞書を渡すと、HTTPS の時に "cert" へ証明書を入れる。
    """
    tls = {} if tls is None else tls
    opener = opener or urllib.request.build_opener(_NoRedirect, _CertHTTPSHandler(tls))
    start = url
    for _ in range(MAX_REDIRECTS + 1):
        _check_host(urllib.parse.urlsplit(url).hostname, resolve)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"})
        try:
            res = opener.open(req, timeout=TIMEOUT_SEC)
        except urllib.error.HTTPError as e:
            res = e
        except (OSError, ValueError) as e:
            raise ValueError(f"サイトにつながりませんでした({type(e).__name__})")
        status = res.status if hasattr(res, "status") else res.code
        headers = {}
        for k, v in res.headers.items():
            k = k.lower()
            headers[k] = headers[k] + "\n" + v if k in headers else v
        location = headers.get("location")
        if 300 <= status < 400 and location:
            res.close()
            nxt = urllib.parse.urljoin(url, location)
            if not _same_site(start, nxt) or urllib.parse.urlsplit(nxt).scheme not in ("http", "https"):
                raise ValueError(f"別のサイト({urllib.parse.urlsplit(nxt).hostname})へ転送されたため、そこで止めました")
            url = nxt
            continue
        try:
            body = res.read(MAX_BODY)
        except OSError:
            body = b""
        res.close()
        charset = res.headers.get_content_charset() or "utf-8"
        try:
            html = body.decode(charset, errors="replace")
        except LookupError:
            html = body.decode("utf-8", errors="replace")
        return url, status, headers, html
    raise ValueError("転送が多すぎるため止めました")


def analyze(url, status, headers, html, cert=None):
    info = SiteInfo(url, status)
    seen = {}
    for name, header, pattern, group in TECH_RULES:
        source = html if header is None else headers.get(header, "")
        for line in (source.split("\n") if header else [source]):
            m = re.search(pattern, line)
            if not m:
                continue
            version = m.group(group) if group and m.lastindex and m.group(group) else None
            evidence = f"応答ヘッダ {header}: {line.strip()[:80]}" if header else "ページのHTML"
            if name in seen:
                if version and not seen[name].version:
                    seen[name].version, seen[name].evidence = version, evidence
            else:
                seen[name] = Tech(name, version, evidence)
                info.techs.append(seen[name])
            break
    # WordPress・Laravel 等は PHP で動く
    if any(t.name in PHP_TECHS - {"PHP"} for t in info.techs) and not info.tech("PHP"):
        info.techs.append(Tech("PHP", None, "PHPで動くソフトが見つかったため"))
    hosted = set()
    for name, kind, header, pattern in HOSTING_RULES:
        if name in hosted:
            continue
        source = html if header is None else headers.get(header, "")
        if source and re.search(pattern, source):
            hosted.add(name)
            info.hostings.append(Hosting(name, kind, f"応答ヘッダ {header}" if header else "ページのHTML"))
    for header in ("server", "x-powered-by"):
        for m in _SERVER_VERSION_RE.finditer(headers.get(header, "")):
            info.exposed_versions.append(f"{m.group(1)}/{m.group(2)}")
    if cert and cert.get("notAfter"):
        try:
            info.cert_expires = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"]), datetime.timezone.utc).date()
        except ValueError:
            pass
    info.advice = header_advice(info.https, headers)
    return info


def header_advice(https, headers):
    """同じ応答のヘッダから、あると安心な設定で無いものを挙げる。どれも無くてもすぐ危険ではない。"""
    out = []
    csp = headers.get("content-security-policy", "")
    if https and "strict-transport-security" not in headers:
        out.append(("HSTS", "Strict-Transport-Security が無い(ブラウザに「必ずHTTPSで開く」と覚えさせる設定)"))
    if not csp:
        out.append(("CSP", "Content-Security-Policy が無い(読み込んでよいスクリプトの出どころを決め、"
                           "書き換え攻撃の被害を減らす設定)"))
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        out.append(("クリックジャッキング対策", "X-Frame-Options(または CSP の frame-ancestors)が無い"
                                         "(他のサイトに自分のページを透明にはめ込まれて、ボタンを押させる攻撃を防ぐ設定)"))
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(("nosniff", "X-Content-Type-Options: nosniff が無い(ファイルの種類の取り違えを防ぐ設定)"))
    for line in headers.get("set-cookie", "").split("\n"):
        name = line.split("=", 1)[0].strip()
        if not name or not _SESSION_COOKIE_RE.search(name):
            continue
        attrs = {a.strip().split("=")[0].lower() for a in line.split(";")[1:]}
        missing = [a for a, need in (("Secure", https), ("HttpOnly", True)) if need and a.lower() not in attrs]
        if missing:
            out.append((f"Cookie {name}", f"ログイン状態の Cookie「{name}」に {'・'.join(missing)} が付いていない"
                                          "(盗まれにくくする印)"))
    return out


_SESSION_COOKIE_RE = re.compile(r"sess|sid|token|auth|login", re.I)


def check_site(url, resolve=socket.getaddrinfo, opener=None):
    tls = {}
    final, status, headers, html = fetch(normalize_url(url), resolve, opener, tls)
    return analyze(final, status, headers, html, tls.get("cert"))


def main_hosting(info):
    """説明に使う置き場所を1つ選ぶ(サービスの種類を優先し、CDN と自前サーバーは最後)。"""
    order = [HOST_BUILDER, HOST_PAAS, HOST_STATIC, HOST_SELF, HOST_CDN]
    return min(info.hostings, key=lambda h: order.index(h.kind)) if info.hostings else None
