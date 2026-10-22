"""前回の診断結果を覚えておき、「前回から新しく見つかったもの」「直ったもの」を出す。

保存先はこのPCの中だけ(%LOCALAPPDATA%\\WebShindan)。秘密の鍵の値は保存しない(場所と種類だけ)。
"""

import datetime
import json
import os
from dataclasses import dataclass, field

MAX_ENTRIES = 50


def app_dir():
    # WEBSHINDAN_HOME はテスト用(本物の保存先を汚さないため)
    base = os.environ.get("WEBSHINDAN_HOME") or os.path.join(
        os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "WebShindan")
    os.makedirs(base, exist_ok=True)
    return base


def default_path():
    return os.path.join(app_dir(), "history.json")


def key_of(url, folder, php_text):
    folder = os.path.normcase(os.path.abspath(folder)) if folder else ""
    return json.dumps([url.strip().lower(), folder, php_text.strip()], ensure_ascii=False)


@dataclass
class Changes:
    previous_when: str                          # 前回の日時("2026-10-22 10:00")
    new: list = field(default_factory=list)     # [文章] 前回から新しく見つかったもの
    fixed: list = field(default_factory=list)   # [文章] 前回はあって、今回は無いもの


def _read(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def compare(path, key, items):
    """items: {ID: 文章}。前回が無ければ None。"""
    prev = _read(path).get(key)
    if not prev:
        return None
    old = prev.get("items", {})
    new = [i for i in items if i not in old]
    fixed = [i for i in old if i not in items]
    # 同じ脆弱性の「部品の脆弱性(pkg:)」と「攻撃に使われている(kev:)」が一緒に動いた時は、1つだけ出す
    new = [i for i in new if not (i.startswith("pkg:") and "kev:" + i[4:] in new)]
    fixed = [i for i in fixed if not (i.startswith("kev:") and "pkg:" + i[4:] in fixed)]
    return Changes(prev.get("when", ""), [items[i] for i in new], [old[i] for i in fixed])


def save(path, key, items, level, when=None):
    data = _read(path)
    data.pop(key, None)
    data[key] = {"when": f"{when or datetime.datetime.now():%Y-%m-%d %H:%M}", "level": level, "items": items}
    while len(data) > MAX_ENTRIES:  # 古いものから消す(辞書は入れた順を保つ)
        data.pop(next(iter(data)))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)
