"""PHP・Node.js・Go の本体が、公式が出した最新の修正版より古くないかを調べる。

CVE の一覧は持たない。公式のリリース情報は公式が毎回更新するので、新しい脆弱性が出てもツールの更新が要らない。
外に送るものは無い(一覧をまるごと取るだけ。PHP は大きい方の番号 "8" だけ URL に入る)。
"""

import datetime
import json
import re
import urllib.request
from dataclasses import dataclass, field

from . import core

PHP_URL = "https://www.php.net/releases/index.php?json&version={}&max=1000"
NODE_URL = "https://nodejs.org/dist/index.json"
GO_URL = "https://go.dev/dl/?mode=json&include=all"
TIMEOUT_SEC = 30

PRODUCT_LABELS = {"php": "PHP", "nodejs": "Node.js", "go": "Go"}
SOURCE_LABELS = {"php": "php.net", "nodejs": "nodejs.org", "go": "go.dev"}

_NUMS_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


@dataclass
class Release:
    version: str        # "8.3.36"
    date: str           # "2026-10-21"。わからなければ ""


@dataclass
class Target:
    """比べる版。同じ製品・同じ版は1つにまとめる。"""
    product: str
    version: str | None          # "8.3.12"。系列だけの指定なら None
    cycle: str                   # "8.3" / "20" / "1.26"
    wheres: list = field(default_factory=list)
    backport: bool = False       # OS配布元の版・自分で管理するサーバー(番号を変えずに修正を取り込むことがある)


@dataclass
class ReleaseResult:
    target: Target
    level: str | None    # core.CHECK / core.SAFE。None は注意書きだけ
    message: str
    fix: str | None = None   # これ以上に上げる版

    @property
    def label(self):
        return f"{PRODUCT_LABELS[self.target.product]} {self.target.version or self.target.cycle}"


def _get_json(url, opener):
    req = urllib.request.Request(url, headers={"User-Agent": "web-shindan"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        return json.loads(res.read().decode("utf-8"))


def _key(version):
    return tuple(int(x) for x in re.findall(r"\d+", version))


def cycle_of(product, version):
    nums = version.split(".")
    return nums[0] if product == "nodejs" else ".".join(nums[:2])


# --- 公式のリリース情報 → {系列: 最新の修正版} ---

def parse_php(rows):
    """PHP はリリースごとに tags(security 等)が付く。系列ごとに security の付いた最新版を選ぶ。"""
    table = {}
    for version, info in rows.items():
        if not _NUMS_RE.fullmatch(version) or "security" not in (info.get("tags") or []):
            continue
        try:
            date = datetime.datetime.strptime(info.get("date", ""), "%d %b %Y").date().isoformat()
        except ValueError:
            date = ""
        cycle = cycle_of("php", version)
        if cycle not in table or _key(version) > _key(table[cycle].version):
            table[cycle] = Release(version, date)
    return table


def parse_node(rows):
    """Node.js は版ごとに security: true/false が付く。系列ごとに security の付いた最新版を選ぶ。"""
    table = {}
    for r in rows:
        version = str(r.get("version", "")).lstrip("v")
        if not r.get("security") or not _NUMS_RE.fullmatch(version):
            continue
        cycle = cycle_of("nodejs", version)
        if cycle not in table or _key(version) > _key(table[cycle].version):
            table[cycle] = Release(version, str(r.get("date", "")))
    return table


def parse_go(rows):
    """Go は修正の種類の印が無い。系列ごとの最新の正式版を選ぶ(go1.20 のような .0 無しの書き方もある)。"""
    table = {}
    for r in rows:
        m = re.fullmatch(r"go(\d+\.\d+)(?:\.(\d+))?", str(r.get("version", "")))
        if not r.get("stable") or not m:
            continue
        version = f"{m.group(1)}.{m.group(2) or 0}"
        cycle = m.group(1)
        if cycle not in table or _key(version) > _key(table[cycle].version):
            table[cycle] = Release(version, "")
    return table


def load(product, majors=(), opener=urllib.request.urlopen):
    """{系列: Release} を返す。取れなければ例外(呼び出し側で「比べられませんでした」にする)。"""
    if product == "php":
        table = {}
        for major in sorted(set(majors)):
            table.update(parse_php(_get_json(PHP_URL.format(major), opener)))
    elif product == "nodejs":
        table = parse_node(_get_json(NODE_URL, opener))
    else:
        table = parse_go(_get_json(GO_URL, opener))
    if not table:
        raise ValueError("公式のリリース情報を読めませんでした")
    return table


# --- 比べる版を集める ---

def collect(php_inputs=(), runtimes=(), server_self=False):
    """php_inputs: [(場所の説明, 入力された文字)]。runtimes: scanners.Runtime の一覧。"""
    targets = {}

    def add(product, version, cycle, where, backport):
        t = targets.setdefault((product, version, cycle), Target(product, version, cycle))
        if where not in t.wheres:
            t.wheres.append(where)
        t.backport = t.backport or backport

    for where, text in php_inputs:
        v = core.parse_version(text or "")
        if v is not None:
            add("php", v.text, v.branch, where, v.is_distro_build or server_self)
    for r in runtimes:
        if r.product not in PRODUCT_LABELS or not r.exact or not r.cycle:
            continue  # 「これ以上」の下限だけの指定は、実際に動く版がわからないので比べない
        m = _NUMS_RE.search(r.raw)
        version = ".".join(m.groups()) if m else None
        if version and cycle_of(r.product, version) != r.cycle:
            version = None
        add(r.product, version, r.cycle, r.source, False)
    # 同じ系列に版のわかる指定があれば、系列だけの指定の注意書きは出さない
    known = {(t.product, t.cycle) for t in targets.values() if t.version}
    return [t for t in targets.values() if t.version or (t.product, t.cycle) not in known]


# --- 判定 ---

def check(target, table, error=None):
    """table: {系列: Release}。error: 取得に失敗した理由(table は None)。"""
    name = PRODUCT_LABELS[target.product]
    if table is None:
        return ReleaseResult(target, core.CHECK, f"{name}の最新の修正版と比べられませんでした({error})。"
                                                 "ネットにつないでもう一度試してください")
    latest = table.get(target.cycle)
    if latest is None:
        newest = max((_key(c) for c in table), default=())
        if _key(target.cycle) > newest:
            return ReleaseResult(target, core.SAFE, "公式の情報より新しい系列です")
        return ReleaseResult(target, core.CHECK, f"{name} {target.cycle} の修正版の情報が見つかりませんでした")
    when = f"({latest.date})" if latest.date else ""
    if target.version is None:
        return ReleaseResult(target, None, f"系列だけの指定です。サーバーを作り直すと、その時の最新版"
                                           f"(今は {latest.version}{when})になります。古いまま動き続けていないか"
                                           "確認してください")
    if _key(target.version) >= _key(latest.version):
        return ReleaseResult(target, core.SAFE, f"最新の修正版({latest.version}{when})を取り込んでいます")
    if target.product == "go":
        msg = (f"新しい修正版 {latest.version} が出ています。{latest.version} 以上で作り直してください"
               "(Goは修正の種類を公開データで区別していないため、セキュリティの修正を含むかは公式のお知らせで確認できます)")
    else:
        msg = (f"公式のセキュリティ修正版 {latest.version}{when}が出ていますが、まだ取り込まれていません。"
               f"{latest.version} 以上に上げてください")
    if target.backport:
        msg += ("。ただし、OS配布元の版やご自身で管理するサーバーでは、番号を変えずに修正だけを取り込むことがあります。"
                "OSの更新で直っていないかも確認してください")
    return ReleaseResult(target, core.CHECK, msg, latest.version)
