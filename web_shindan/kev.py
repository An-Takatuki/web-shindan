"""CISA KEV(米国 CISA が公開している「実際に攻撃に使われている脆弱性」の一覧)を取る。

一覧をまるごと取るだけで、こちらからは何も送らない。CISA が毎日更新するので、ツールの更新は要らない。
"""

import json
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT_SEC = 30


def parse(body):
    cves = {str(v.get("cveID", "")).upper() for v in body.get("vulnerabilities", [])}
    cves.discard("")
    if not cves:
        raise ValueError("KEV の一覧を読めませんでした")
    return cves


def load(opener=urllib.request.urlopen):
    """CVE番号の集合を返す。取れなければ例外。"""
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "web-shindan"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        return parse(json.loads(res.read().decode("utf-8")))


def mark(vuln_map, cves):
    """OSV の脆弱性(別名の CVE を含む)が KEV に載っていれば exploited にする。"""
    for vulns in vuln_map.values():
        for v in vulns:
            v.exploited = any(i.upper() in cves for i in v.ids)
