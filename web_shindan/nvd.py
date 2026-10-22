"""NVD(米国の脆弱性データベース)から最新の影響範囲を取ってくる。"""

import json
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
TIMEOUT_SEC = 20


def parse_fixed_versions(record):
    """NVD の CVE レコードから {"8.3": "8.3.36", ...} を取り出す。

    php-src の affected で「X.Y.* は lessThan より前が影響あり」の形だけを読む。
    読めない形が混ざっていたら、その項目は無視する。
    """
    fixed = {}
    for affected in record.get("affected", []):
        for data in affected.get("affectedData", []):
            if data.get("packageName") != "php-src":
                continue
            for v in data.get("versions", []):
                branch = v.get("version", "")
                less_than = v.get("lessThan")
                if v.get("status") != "affected" or not less_than or not branch.endswith(".*"):
                    continue
                fixed[branch[:-2]] = less_than
    return fixed


def fetch_cve(cve_id, opener=urllib.request.urlopen):
    """1件取得して (fixed辞書, 説明文) を返す。失敗したら例外。"""
    req = urllib.request.Request(NVD_URL.format(cve_id), headers={"User-Agent": "web-shindan/0.1"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        body = json.loads(res.read().decode("utf-8"))
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        raise ValueError(f"{cve_id} が NVD に見つからない")
    record = vulns[0]["cve"]
    fixed = parse_fixed_versions(record)
    if not fixed:
        raise ValueError(f"{cve_id} の影響範囲を読み取れない")
    return fixed


def load_latest(watched, opener=urllib.request.urlopen):
    """内蔵データの fixed を NVD の最新値で置き換えたリストを返す。

    1件でも取れなければ例外にして、呼び出し側で内蔵データに切り替える
    (一部だけ新しいデータが混ざるのを避けるため)。
    """
    latest = []
    for cve in watched:
        updated = dict(cve)
        updated["fixed"] = fetch_cve(cve["id"], opener)
        latest.append(updated)
    return latest
