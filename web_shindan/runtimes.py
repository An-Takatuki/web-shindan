"""実行環境(Node.js・PHP・Python・Go・Ruby)の版がサポート期限切れかを判定する。

期限は endoflife.date から取る。「最新版」欄は更新が遅れることがあるので使わず、期限(eol)だけを使う。
"""

import datetime
import json
import urllib.request
from dataclasses import dataclass

from . import core, data

EOL_URL = "https://endoflife.date/api/{}.json"
TIMEOUT_SEC = 20
SOON_DAYS = 90

PRODUCT_LABELS = {"nodejs": "Node.js", "php": "PHP", "python": "Python", "go": "Go", "ruby": "Ruby"}


@dataclass
class RuntimeResult:
    product: str
    cycle: str | None
    sources: list        # この指定が書かれていた場所
    exact: bool
    level: str | None    # core.DANGER / core.CHECK / core.SAFE。None は判定の対象外(版が読めない等)
    message: str

    @property
    def label(self):
        return f"{PRODUCT_LABELS[self.product]} {self.cycle or '(版不明)'}"


def load_table(opener=urllib.request.urlopen):
    """{製品: {系列: 期限}} を返す。1つでも取れなければ例外(呼び出し側で内蔵の控えに切り替える)。"""
    table = {}
    for product in PRODUCT_LABELS:
        req = urllib.request.Request(EOL_URL.format(product), headers={"User-Agent": "web-shindan"})
        with opener(req, timeout=TIMEOUT_SEC) as res:
            rows = json.loads(res.read().decode("utf-8"))
        table[product] = {str(r["cycle"]): r["eol"] for r in rows}
    return table


def _cycle_key(cycle):
    return tuple(int(x) for x in str(cycle).split(".") if x.isdigit())


def is_expired(product, cycle, table, today=None):
    """サポート期限を過ぎた系列か。期限の情報が無ければ False。"""
    today = today or datetime.date.today()
    eol = table.get(product, {}).get(cycle)
    return eol is True or (isinstance(eol, str) and datetime.date.fromisoformat(eol) < today)


def check(product, cycle, exact, sources, table, today=None):
    today = today or datetime.date.today()
    name = PRODUCT_LABELS[product]
    if cycle is None:
        return RuntimeResult(product, cycle, sources, exact, None, "版を読み取れなかったため、期限は確認していません")
    cycles = table.get(product, {})
    eol = cycles.get(cycle)
    if eol is None:
        newest = max((_cycle_key(c) for c in cycles), default=())
        if _cycle_key(cycle) > newest:
            return RuntimeResult(product, cycle, sources, exact, core.SAFE, "期限の情報より新しい版です")
        return RuntimeResult(product, cycle, sources, exact, core.CHECK,
                             f"{name} {cycle} のサポート期限の情報が見つかりませんでした")
    expired = eol is True or (isinstance(eol, str) and datetime.date.fromisoformat(eol) < today)
    if expired:
        when = f"({eol} に終了)" if isinstance(eol, str) else ""
        if exact:
            return RuntimeResult(product, cycle, sources, exact, core.DANGER,
                                 f"サポートが終わっています{when}。新しく見つかった脆弱性が直されないので、"
                                 "サポート中の版に上げてください")
        return RuntimeResult(product, cycle, sources, exact, core.CHECK,
                             f"サポートが終わった {name} {cycle}{when} でも動く指定になっています。"
                             "実際にサーバーで動いている版がサポート中か確認してください")
    if isinstance(eol, str) and (datetime.date.fromisoformat(eol) - today).days <= SOON_DAYS:
        return RuntimeResult(product, cycle, sources, exact, core.SAFE,
                             f"サポート中ですが、もうすぐ終わります({eol})。早めに新しい版へ移る準備をしてください")
    until = f"({eol} まで)" if isinstance(eol, str) else ""
    return RuntimeResult(product, cycle, sources, exact, core.SAFE, f"サポート中です{until}")


def check_all(runtimes, table, today=None):
    """同じ製品・同じ系列・同じ種類の指定はまとめて判定する。"""
    groups = {}
    for r in runtimes:
        groups.setdefault((r.product, r.cycle, r.exact), []).append(r.source)
    return [check(p, c, e, srcs, table, today) for (p, c, e), srcs in groups.items()]


def snapshot_table():
    return data.EOL_SNAPSHOT
