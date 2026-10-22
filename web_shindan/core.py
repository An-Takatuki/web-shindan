"""判定ロジック本体。画面(gui.py)からもテストからも同じ関数を呼ぶ。"""

import re
from dataclasses import dataclass, field

from . import data

DANGER = "危険"
CHECK = "要確認"
SAFE = "対象外"
INPUT_ERROR = "入力エラー"

SERVER_RENTAL = "rental"    # レンタルサーバー(Xserver・さくら・ロリポップ等)
SERVER_SELF = "self"        # 自分/会社で管理しているサーバー(Ubuntu等)
SERVER_UNKNOWN = "unknown"  # わからない(制作会社にお任せ等)

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)([^\s]*)")
_BRANCH_ONLY_RE = re.compile(r"(\d+)\.(\d+)(?!\.\d)")


@dataclass
class ParsedVersion:
    numbers: tuple      # (8, 3, 12)
    suffix: str         # "-0ubuntu0.24.04.5" など。無ければ ""

    @property
    def text(self):
        return ".".join(map(str, self.numbers))

    @property
    def branch(self):
        return f"{self.numbers[0]}.{self.numbers[1]}"

    @property
    def is_distro_build(self):
        """末尾に "-1ubuntu…" "~deb12u1" 等がある = OS配布元が作った版(修正の取り込みがありうる)"""
        return self.suffix[:1] in ("-", "~", "+")


@dataclass
class CveResult:
    cve_id: str
    affected: bool
    reason: str


@dataclass
class Result:
    level: str
    headline: str
    version_text: str = ""
    details: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    inquiry: str = ""


def parse_version(text):
    """"PHP 8.3.12" "8.3.6-0ubuntu0.24.04.5" 等から版を読む。読めなければ None。"""
    m = _VERSION_RE.search(text.strip())
    if not m:
        return None
    return ParsedVersion(tuple(int(m.group(i)) for i in (1, 2, 3)), m.group(4))


def _as_tuple(version_text):
    return tuple(int(x) for x in version_text.split("."))


def check_cve(version, cve):
    """1件の CVE について影響があるかを返す。"""
    major_minor = version.numbers[:2]
    if major_minor < data.OLDEST_SUPPORTED_BRANCH:
        return CveResult(cve["id"], True,
                         f"PHP {version.branch} は公式サポートが終了していて、公式の修正版が出ない")
    fixed = cve["fixed"].get(version.branch)
    if fixed is None:
        newest = max(_as_tuple(b) for b in cve["fixed"])
        if major_minor > newest:
            return CveResult(cve["id"], False,
                             f"PHP {version.branch} は修正済みの新しい系列(データ上は影響なし)")
        return CveResult(cve["id"], True,
                         f"PHP {version.branch} の情報がデータに無いため、安全とは言えない")
    if version.numbers < _as_tuple(fixed):
        return CveResult(cve["id"], True, f"{fixed} より前の版なので影響あり")
    return CveResult(cve["id"], False, f"{fixed} 以降の修正済みの版")


def judge(version_input, server_type, watched=None, found_in=None):
    """入力された版とサーバーの種類から、総合判定を返す。

    found_in: 自動検出で拾った版なら、その場所の説明("このPC: C:\\xampp\\php\\php.exe" 等)。
    """
    result = _judge(version_input, server_type, watched)
    if found_in and result.level != INPUT_ERROR:
        if found_in == "サイトの応答":  # 公開中のサイトのヘッダに出ていた版(開発環境ではない)
            result.details.insert(0, "このバージョンは、公開中のサイトの応答に表示されていたものです。")
        else:
            result.details.insert(0, f"このバージョンは開発環境({found_in})で見つけたものです。"
                                     "本番サイトのPHPは違うバージョンのことがあるので、本番は別に確認してください。")
    return result


def _judge(version_input, server_type, watched):
    watched = watched if watched is not None else data.WATCHED_CVES
    if not version_input.strip():
        return Result(INPUT_ERROR, "PHPのバージョンを入力してください",
                      details=["下の「バージョンの調べ方」を参考に、例: 8.3.12 のように入力してください。"])
    version = parse_version(version_input)
    if version is None:
        if _BRANCH_ONLY_RE.search(version_input):
            return Result(INPUT_ERROR, "最後の数字まで入力してください",
                          details=["「8.3」だけでは判定できません。「8.3.12」のように、3つ目の数字まで必要です。",
                                   "管理画面で「8.3」までしか表示されない場合は、サーバー会社のお知らせで"
                                   "修正版(下の一覧)に更新済みかを確認してください。"])
        return Result(INPUT_ERROR, "バージョンを読み取れませんでした",
                      details=["例: 8.3.12 のように、数字とピリオドで入力してください。"])

    cves = [check_cve(version, cve) for cve in watched]
    affected = [c for c in cves if c.affected]
    eol = version.numbers[:2] < data.OLDEST_SUPPORTED_BRANCH

    if not affected:
        result = Result(SAFE, "今回の脆弱性(PHP2Shell)の対象外です", version.text, cves=cves)
        result.details.append("入力された版は、今回の2件が修正された後の版です。")
        result.details.append("※ 今回の2件以外の脆弱性までは判定していません。")
        result.steps = ["特に作業は不要です。今後もサーバー会社・制作会社からのお知らせは確認してください。"]
        return result

    backport_possible = version.is_distro_build or server_type == SERVER_SELF
    if backport_possible:
        result = Result(CHECK, "番号の上では対象です。OSの更新で直っているか確認が必要です",
                        version.text, cves=cves)
        result.details.append("Ubuntu・Debian・Red Hat などは、バージョン番号を変えずに修正だけを"
                              "取り込むことがあります。番号だけでは「直っているか」を判断できません。")
        if version.is_distro_build:
            result.details.append(f"入力された版の末尾「{version.suffix}」は、OS配布元が作った版の目印です。")
        result.steps = [
            "サーバーの管理者に、OSのアップデート(例: apt upgrade / dnf upgrade)を行い、"
            "PHPを再起動したかを確認してもらう",
            "OS配布元のセキュリティ情報(Ubuntu Security Notices など)で、"
            "CVE-2026-109618 と CVE-2026-109619 が修正済みかを確認する",
            "すぐに確認・更新できない場合は、サイトを一時停止することも検討する"
            "(英国NCSCは、修正できないシステムはネットから外すよう呼びかけています)",
        ]
    else:
        result = Result(DANGER, "今回の脆弱性(PHP2Shell)の対象です。早めの対応が必要です",
                        version.text, cves=cves)
        result.details.append("この脆弱性は、ログインなしで外部からサイトを乗っ取られるおそれがある、"
                              "とても深刻なものです(深刻度 9.2 / 10)。")
        if server_type == SERVER_RENTAL:
            result.details.append("レンタルサーバーでは、番号を変えずに修正済みのこともあります。"
                                  "まずはサーバー会社のお知らせを確認してください。")
            result.steps = [
                "契約しているレンタルサーバー会社のお知らせ・障害情報ページで、"
                "PHPの脆弱性(PHP2Shell)への対応状況を確認する",
                "サーバーの管理画面で、PHPのバージョンを修正版(下の一覧)に切り替えられるか確認する",
                "サイトを制作会社に作ってもらった場合は、切り替えてもサイトが壊れないか、"
                "下の「問い合わせ文」で相談する",
            ]
        else:
            result.steps = [
                "サイトを作った制作会社、またはサーバーの管理者に、下の「問い合わせ文」を送って対応を依頼する",
                "誰が管理しているかわからない場合は、サーバーの請求書や契約メールから契約先を探す",
            ]
    if eol:
        result.details.append(f"PHP {version.branch} は公式サポートが終わっているため、"
                              "修正版のある 8.2 以降への移行が必要です"
                              "(移行するとサイトが動かなくなることがあるので、制作会社と相談してください)。")
    result.inquiry = make_inquiry(version, result.level)
    return result


def make_inquiry(version, level):
    """制作会社・サーバー管理者への問い合わせ文(コピーして使う)。"""
    return (
        "お世話になっております。\n"
        "2026年10月21日に修正版が公開されたPHPの脆弱性(通称 PHP2Shell、"
        "CVE-2026-109618 / CVE-2026-109619)について確認させてください。\n"
        f"当方のサイトのPHPのバージョンは {version.text}{version.suffix} と表示されています"
        f"(診断ツールでの判定: {level})。\n"
        "1. このサイトは今回の脆弱性の影響を受けますか。\n"
        "2. 影響がある場合、修正版(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 以降)への更新、"
        "またはOSの更新による修正の予定を教えてください。\n"
        "3. 更新によってサイトの表示や機能に影響が出る可能性はありますか。\n"
        "よろしくお願いいたします。"
    )
