"""WordPress の本体とプラグインを、WordPress.org の公開情報で確認する(キー不要・無料)。

- 本体: 全部の版について「latest / outdated / insecure(安全でない)」を WordPress.org 自身が公開している
- プラグイン: 公式ディレクトリの最新版と、配布停止(理由: セキュリティ問題 等)を確認する。
  プラグインごとの脆弱性データ(Wordfence 等)は登録が必要なので使っていない
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import core, osv

STABLE_CHECK_URL = "https://api.wordpress.org/core/stable-check/1.0/"
PLUGIN_URL = ("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
              "&request%5Bslug%5D={}&request%5Bfields%5D%5Bsections%5D=0")
TIMEOUT_SEC = 20
WORKERS = 8


@dataclass
class CoreResult:
    version: str | None
    status: str | None    # latest / outdated / insecure / None(不明)
    level: str
    message: str


@dataclass
class PluginResult:
    slug: str
    name: str
    version: str | None
    latest: str | None
    level: str
    message: str


def _get_json(url, opener):
    req = urllib.request.Request(url, headers={"User-Agent": "web-shindan"})
    with opener(req, timeout=TIMEOUT_SEC) as res:
        return json.loads(res.read().decode("utf-8"))


def load_core_statuses(opener=urllib.request.urlopen):
    return _get_json(STABLE_CHECK_URL, opener)


def check_core(version, statuses):
    if not version:
        return CoreResult(version, None, core.CHECK, "WordPress の版を読み取れませんでした。管理画面の「ダッシュボード」"
                                                    "→「更新」で版を確認してください")
    status = statuses.get(version)
    if status is None:
        # "6.4" のように末尾 .0 が省かれている書き方にも対応する
        status = statuses.get(re.sub(r"\.0$", "", version)) or statuses.get(version + ".0")
    if status == "insecure":
        return CoreResult(version, status, core.DANGER,
                          f"WordPress {version} は、WordPress公式が「安全でない版」としています。すぐに更新してください")
    if status == "outdated":
        return CoreResult(version, status, core.CHECK,
                          f"WordPress {version} は最新版ではありません(安全でない版ではありません)。更新をおすすめします")
    if status == "latest":
        return CoreResult(version, status, core.SAFE, f"WordPress {version} は最新版です")
    return CoreResult(version, None, core.CHECK, f"WordPress {version} は公式の一覧に無い版です。版を確認してください")


def check_plugin(slug, name, version, opener=urllib.request.urlopen):
    try:
        info = _get_json(PLUGIN_URL.format(urllib.parse.quote(slug)), opener)
    except urllib.error.HTTPError as e:
        # 配布停止・存在しないプラグインは 404 で返り、理由は本文の JSON に入っている(2026-10-22 実測)
        try:
            info = json.loads(e.read().decode("utf-8"))
        except (ValueError, OSError):
            return PluginResult(slug, name, version, None, core.CHECK, f"確認できませんでした(HTTP {e.code})")
    except Exception as e:  # 通信失敗はこのプラグインだけ「確認できず」にする
        return PluginResult(slug, name, version, None, core.CHECK, f"確認できませんでした({type(e).__name__})")
    if info.get("error") == "closed" or info.get("closed"):
        reason = info.get("reason_text") or info.get("reason") or "不明"
        level = core.DANGER if info.get("reason") == "security-issue" else core.CHECK
        return PluginResult(slug, name, version, None, level,
                            f"公式の配布が停止されています(理由: {reason}、{info.get('closed_date') or '日付不明'})。"
                            "今後更新されないので、別のプラグインへの置き換えを検討してください")
    if info.get("error"):
        return PluginResult(slug, name, version, None, core.CHECK,
                            "公式ディレクトリに無いプラグインです(有料・自作の可能性)。"
                            "作った会社の更新情報を確認してください")
    latest = info.get("version")
    if version and latest and osv.version_key(version) < osv.version_key(latest):
        return PluginResult(slug, name, version, latest, core.CHECK,
                            f"新しい版 {latest} が出ています。古い版には脆弱性が見つかっていることが多いので、更新してください")
    if not version:
        return PluginResult(slug, name, version, latest, core.CHECK, "インストールされている版を読み取れませんでした")
    return PluginResult(slug, name, version, latest, core.SAFE, "最新版です")


def check_plugins(plugins, opener=urllib.request.urlopen):
    with ThreadPoolExecutor(WORKERS) as pool:
        return list(pool.map(lambda p: check_plugin(*p, opener=opener), plugins))
