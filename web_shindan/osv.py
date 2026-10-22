"""OSV.dev(Google が運営する無料の脆弱性データベース)で部品を照合する。

外に送るのは「部品の種類・名前・版」だけ。
"""

import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 1000
WORKERS = 8
TIMEOUT_SEC = 30

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}
SEVERITY_LABELS = {4: "重大", 3: "高", 2: "中", 1: "低", 0: "不明"}


@dataclass
class Vuln:
    id: str
    aliases: list
    summary: str
    severity: int          # 0〜4(SEVERITY_LABELS)
    fixed: str | None      # この部品の今の版から見て、一番近い直った版
    ids: set = field(default_factory=set)        # 同じ脆弱性の別名を含む全ID
    intervals: list = field(default_factory=list)  # 影響範囲 [(introduced, 終わりの版 or None, 終わりを含むか)]
    versions: set = field(default_factory=set)     # 影響ありと個別に列挙された版
    exploited: bool = False                        # CISA KEV に載っている(実際に攻撃に使われている)
    details: str = ""                              # データベースの説明文(多くは英語)

    @property
    def cve(self):
        return next((a for a in sorted(self.ids) if a.startswith("CVE-")), "")

    def affects(self, version):
        if version in self.versions or version.lstrip("vV") in self.versions:
            return True
        key = version_key(version)
        for intro, end, inclusive in self.intervals:
            if key < version_key(intro):
                continue
            if end is None or key < version_key(end) or (inclusive and key == version_key(end)):
                return True
        return False


def min_safe_version(vulns, current):
    """今の版より新しく、どの脆弱性の影響範囲にも入らない一番低い「直った版」。無ければ None。"""
    now = version_key(current)
    candidates = {end for v in vulns for _, end, inclusive in v.intervals
                  if end and not inclusive and version_key(end) > now}
    for c in sorted(candidates, key=version_key):
        if not any(v.affects(c) for v in vulns):
            return c
    return None


def version_key(v):
    """ざっくりした版の比較用キー。"1.2.10" > "1.2.9"、"2.0.0-rc1" < "2.0.0"。"""
    v = v.lstrip("vV")
    m = re.match(r"^([0-9.]+)(.*)$", v)
    main, rest = (m.group(1), m.group(2)) if m else ("", v)
    nums = tuple(int(x) for x in main.split(".") if x.isdigit())
    nums = nums + (0,) * (6 - len(nums))
    pre = bool(re.match(r"^[-.]?(a|b|rc|alpha|beta|pre|dev|preview|canary|next)", rest, re.IGNORECASE))
    return nums, 0 if pre else 1


def _post(url, payload, opener):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "web-shindan"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        return json.loads(res.read().decode("utf-8"))


def _get(url, opener):
    req = urllib.request.Request(url, headers={"User-Agent": "web-shindan"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        return json.loads(res.read().decode("utf-8"))


def query_ids(packages, opener=urllib.request.urlopen):
    """版の確定した部品それぞれについて、該当する脆弱性IDの一覧を返す(packages と同じ順)。"""
    results = []
    for start in range(0, len(packages), BATCH_SIZE):
        chunk = packages[start:start + BATCH_SIZE]
        body = _post(BATCH_URL, {"queries": [
            {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version} for p in chunk]}, opener)
        for r in body.get("results", []):
            results.append([v["id"] for v in r.get("vulns", [])])
    if len(results) != len(packages):
        raise ValueError("OSV の応答の件数が合わない")
    return results


def _severity(record):
    level = SEVERITY_ORDER.get(str((record.get("database_specific") or {}).get("severity", "")).upper(), 0)
    if not level:
        for affected in record.get("affected", []):
            level = max(level, SEVERITY_ORDER.get(
                str((affected.get("ecosystem_specific") or {}).get("severity", "")).upper(), 0))
    return level


def _affected_ranges(record, package):
    """この部品についての影響範囲 (intervals, versions) を読む。GIT の範囲(コミット単位)は使わない。"""
    intervals, versions = [], set()
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != package.ecosystem or _norm(pkg.get("name", "")) != _norm(package.name):
            continue
        versions |= set(affected.get("versions", []))
        for r in affected.get("ranges", []):
            if r.get("type") == "GIT":
                continue
            intro = None
            for event in r.get("events", []):
                if "introduced" in event:
                    intro = event["introduced"]
                elif "fixed" in event and intro is not None:
                    intervals.append((intro, event["fixed"], False))
                    intro = None
                elif "last_affected" in event and intro is not None:
                    intervals.append((intro, event["last_affected"], True))
                    intro = None
            if intro is not None:
                intervals.append((intro, None, False))  # まだ直っていない
    return intervals, versions


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_records(ids, opener=urllib.request.urlopen, cache=None):
    cache = {} if cache is None else cache
    missing = [i for i in set(ids) if i not in cache]
    with ThreadPoolExecutor(WORKERS) as pool:
        for vid, record in zip(missing, pool.map(lambda i: _get(VULN_URL.format(i), opener), missing)):
            cache[vid] = record
    return cache


def to_vulns(package, ids, records):
    """IDの一覧を Vuln にし、同じ脆弱性の別名(GHSA と PYSEC 等)を1つにまとめる。"""
    groups = []
    for vid in ids:
        rec = records[vid]
        names = {vid, *rec.get("aliases", [])}
        intervals, versions = _affected_ranges(rec, package)
        v = Vuln(vid, rec.get("aliases", []),
                 (rec.get("summary") or (rec.get("details") or "").strip().split("\n")[0])[:200],
                 _severity(rec), None, names, intervals, versions, details=(rec.get("details") or "").strip())
        for g in groups:
            if g.ids & names:  # 別名どうしは影響範囲を足し合わせる(どちらかで影響ありなら影響あり)
                g.ids |= names
                g.severity = max(g.severity, v.severity)
                g.intervals += v.intervals
                g.versions |= v.versions
                if vid.startswith("GHSA-") and not g.id.startswith("GHSA-"):
                    g.id, g.summary = vid, v.summary or g.summary
                    g.details = v.details or g.details
                g.details = g.details or v.details
                break
        else:
            groups.append(v)
    for g in groups:
        g.fixed = min_safe_version([g], package.version)
    return sorted(groups, key=lambda g: -g.severity)


def check_packages(packages, opener=urllib.request.urlopen):
    """版の確定した部品を照合して {部品の位置: [Vuln, ...]} を返す。通信失敗は例外。"""
    targets = [(i, p) for i, p in enumerate(packages) if p.version]
    ids_list = query_ids([p for _, p in targets], opener)
    records = fetch_records([vid for ids in ids_list for vid in ids], opener)
    return {i: to_vulns(p, ids, records) for (i, p), ids in zip(targets, ids_list) if ids}
