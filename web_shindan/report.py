"""入力ごとの結果をまとめて、総合判定・表示用の文章・AIへの修正依頼文・問い合わせ文を作る。画面には依存しない。"""

import datetime
from dataclasses import dataclass, field

from . import APP_NAME, APP_VERSION, core, data, fingerprint, osv, releases, scanners

LEVEL_RANK = {core.SAFE: 0, core.CHECK: 1, core.DANGER: 2}
LEVEL_TITLES = {core.DANGER: "危険", core.CHECK: "要確認", core.SAFE: "問題は見つからず", core.INPUT_ERROR: "入力不足"}
FOLD = "fold"       # 押すと開け閉めできる題の行(画面)。保存するテキストでは「・」にする
DETAIL = "detail"   # 直前の題の詳しい内容。画面では最初は閉じている
HINT = "hint"       # 画面だけの操作の案内。保存するテキストには入れない
MAX_DETAIL_CHARS = 600
CERT_SOON_DAYS = 14
MAX_CHANGES_SHOWN = 15

# URLから見えた技術と、開発フォルダにあるはずの部品(食い違いの確認用)
TECH_PACKAGES = {
    "Next.js": (scanners.NPM, "next"), "Nuxt": (scanners.NPM, "nuxt"), "Gatsby": (scanners.NPM, "gatsby"),
    "Astro": (scanners.NPM, "astro"), "SvelteKit": (scanners.NPM, "@sveltejs/kit"),
    "Remix": (scanners.NPM, "@remix-run/react"), "Angular": (scanners.NPM, "@angular/core"),
    "Express": (scanners.NPM, "express"), "Laravel": (scanners.PACKAGIST, "laravel/framework"),
    "Django": (scanners.PYPI, "django"), "Ruby on Rails": (scanners.RUBYGEMS, "rails"),
    "Streamlit": (scanners.PYPI, "streamlit"),
}


@dataclass
class PackageFinding:
    package: scanners.Package
    vulns: list
    level: str
    fix_all: str | None   # これ以上に上げれば、見つかった脆弱性が全部直る版(直らないものがあれば None)


@dataclass
class Findings:
    """診断で集めた材料。どれも無ければ None / 空。"""
    url: str = ""
    folder: str = ""
    php_text: str = ""
    scan: scanners.ScanResult | None = None
    vuln_map: dict = field(default_factory=dict)
    osv_error: str | None = None
    php_result: core.Result | None = None        # 手入力の版での判定
    site: fingerprint.SiteInfo | None = None
    site_error: str | None = None
    site_php_result: core.Result | None = None   # サイトの応答に出ていた版での判定
    runtime_results: list = field(default_factory=list)
    runtime_source: str = ""
    wp_core: list = field(default_factory=list)      # [(場所の説明, wordpress.CoreResult)]
    wp_plugins: list = field(default_factory=list)   # [wordpress.PluginResult]
    wp_error: str | None = None
    nvd_source: str = ""
    release_results: list = field(default_factory=list)  # [releases.ReleaseResult]
    kev_error: str | None = None
    leaks: list | None = None    # [leaks.Leak]。開発フォルダを調べなかったら None
    changes: object = None       # history.Changes。前回の結果が無ければ None


@dataclass
class Report:
    level: str
    headline: str
    lines: list = field(default_factory=list)   # [(タグ, 文章)]。タグ "h" は見出し
    ai_prompt: str = ""
    inquiry: str = ""


def package_findings(packages, vuln_map):
    findings = []
    for i, vulns in vuln_map.items():
        p = packages[i]
        # 実際に攻撃に使われている(KEV)ものは、深刻度に関係なく本番用なら危険
        serious = any(v.severity >= 3 or v.exploited for v in vulns)
        level = core.DANGER if serious and not p.dev else core.CHECK
        vulns = sorted(vulns, key=lambda v: (not v.exploited, -v.severity))
        findings.append(PackageFinding(p, vulns, level, osv.min_safe_version(vulns, p.version)))
    return sorted(findings, key=lambda f: (-LEVEL_RANK[f.level], f.package.dev, not _exploited(f),
                                           -max(v.severity for v in f.vulns), f.package.name))


def _vuln_detail(v):
    others = sorted(i for i in v.ids if i != v.id)
    lines = [f"ID: {v.id}" + (f"(別名: {', '.join(others)})" if others else ""),
             f"深刻度: {osv.SEVERITY_LABELS[v.severity]}"
             + (" / 実際に攻撃に使われています(CISA KEV に掲載)" if v.exploited else ""),
             f"この脆弱性が直る版: {v.fixed + ' 以上' if v.fixed else 'まだありません(代わりの部品を検討)'}"]
    if v.details:
        text = " ".join(v.details.split())
        lines.append("説明(データベースの原文): " + (text[:MAX_DETAIL_CHARS] + "…" if len(text) > MAX_DETAIL_CHARS else text))
    lines.append(f"詳しく: https://osv.dev/vulnerability/{v.id}")
    return "".join(f"        {line}\n" for line in lines)


def _exploited(finding):
    return any(v.exploited for v in finding.vulns)


def build(scan=None, vuln_map=None, osv_error=None, php_result=None, php_version_text=""):
    """部品と手入力のPHPだけで作る(段階1の呼び方。テスト用に残している)。"""
    return build_report(Findings(folder=scan.root if scan else "", php_text=php_version_text, scan=scan,
                                 vuln_map=vuln_map or {}, osv_error=osv_error, php_result=php_result))


# --- 注目の脆弱性(PHP2Shell) ---

def _featured_php(f):
    """(判定, 説明, 判定に使った core.Result or None) を返す。判断材料が無ければ None。"""
    if f.php_result is not None:
        return f.php_result.level, f.php_result.headline, f.php_result
    if f.site_php_result is not None:
        r = f.site_php_result
        return r.level, f"サイトの応答に出ていた PHP {r.version_text} で判定: {r.headline}", r
    site_php = f.site is not None and f.site.uses_php
    php_rts = [r for r in (f.scan.runtimes if f.scan else []) if r.product == "php"]
    folder_php = f.scan is not None and (f.scan.php_hints or f.scan.php_requirement or f.scan.wordpress or php_rts)
    for r in php_rts:
        # Dockerfile の php:8.1 等、この系列で動かす指定があり、それがサポート切れなら修正版は出ない
        if r.exact and r.cycle and tuple(int(x) for x in r.cycle.split(".")) < data.OLDEST_SUPPORTED_BRANCH:
            return core.DANGER, (f"開発フォルダで、サポートが終わった PHP {r.cycle} を使う指定になっています"
                                 f"({r.source})。この系列には修正版が出ないので、8.2 以降へ移る必要があります"), None
    if site_php or folder_php:
        where = "サイトの応答" if site_php else "開発フォルダ"
        req = f"(composer.json の指定: PHP {f.scan.php_requirement})" if f.scan and f.scan.php_requirement else ""
        return core.CHECK, (f"{where}から、PHPを使っているようです{req}。サーバーのPHPのバージョンを③に入れると"
                            "判定できます"), None
    if f.site is not None and any(t.name in fingerprint.NON_PHP_TECHS for t in f.site.techs):
        names = "・".join(t.name for t in f.site.techs if t.name in fingerprint.NON_PHP_TECHS)
        return core.SAFE, f"サイトは {names} で動いていて、PHPは使っていないようです(対象外の見込み)", None
    if f.scan is not None:
        return core.SAFE, "開発フォルダにPHPの部品やファイルが無いため、PHPは使っていないようです(対象外の見込み)", None
    if f.site is not None:
        return core.CHECK, ("サイトの応答からは、PHPを使っているかわかりませんでした。開発フォルダか、"
                            "PHPのバージョンを入れると判定できます"), None
    return None


# --- 本体 ---

def build_report(f):
    if f.scan is None and f.php_result is None and f.site is None:
        if f.site_error:
            return Report(core.INPUT_ERROR, "サイトを調べられませんでした",
                          [("", f"{f.site_error}\n"), ("", "URLが合っているか確認するか、②の開発フォルダを入れてください。\n")])
        return Report(core.INPUT_ERROR, "サイトのURL・開発フォルダ・PHPのバージョンのどれかを入れてください",
                      [("", "①にサイトのアドレス、または②の「選ぶ」でAIが作ったプログラムのフォルダを入れてください。\n")])

    lines, levels = [], []
    findings = package_findings(f.scan.packages, f.vuln_map) if f.scan else []
    unknown = [p for p in f.scan.packages if not p.version] if f.scan else []
    add = lines.append

    # 0. 前回からの変化
    if f.changes is not None:
        c = f.changes
        add(("h", f"■ 前回({c.previous_when})からの変化\n"))
        if not c.new and not c.fixed:
            add(("", "前回から変化はありません。\n"))
        if c.new:
            add(("", f"★新しく見つかったもの {len(c.new)}件:\n"))
            add(("", "".join(f"    ・{t}\n" for t in c.new[:MAX_CHANGES_SHOWN])))
            if len(c.new) > MAX_CHANGES_SHOWN:
                add(("", f"    ・ほか {len(c.new) - MAX_CHANGES_SHOWN}件\n"))
        if c.fixed:
            add(("", f"直った(見つからなくなった)もの {len(c.fixed)}件\n"))
        add(("", "\n"))

    # 1. 注目の脆弱性
    featured = _featured_php(f)
    add(("h", "■ ニュースになっている脆弱性\n"))
    if featured:
        level, text, result = featured
        if level != core.INPUT_ERROR:
            levels.append(level)
        add(("", f"・PHP2Shell(PHP本体、2026-10-21修正): 【{LEVEL_TITLES.get(level, level)}】{text}\n"))
        if result is not None and result.level in (core.DANGER, core.CHECK):
            for d in result.details:
                add(("", f"    {d}\n"))
            for s in result.steps:
                add(("", f"    → {s}\n"))

    # 2. サイトの構成(URL)
    if f.site is not None or f.site_error:
        add(("h", "\n■ あなたのサイトは(URLから推定)\n"))
        if f.site_error:
            levels.append(core.CHECK)
            add(("", f"サイトを調べられませんでした: {f.site_error}\n"))
        else:
            _site_section(f, levels, add)

    # 3. 実行環境のサポート期限
    if f.runtime_results:
        add(("h", "\n■ 実行環境(Node.js・PHPなど)のサポート期限\n"))
        for r in f.runtime_results:
            if r.level is not None:
                levels.append(r.level)
            mark = f"【{LEVEL_TITLES[r.level]}】" if r.level else ""
            add(("", f"・{mark}{r.label}: {r.message}(記載: {', '.join(r.sources[:3])})\n"))
        add(("", f"  期限のデータ: {f.runtime_source}\n"))

    # 3.5 本体の修正版(PHP・Node.js・Go)
    if f.release_results:
        add(("h", "\n■ PHP・Node.js・Go 本体の更新\n"))
        for r in f.release_results:
            if r.level is not None:
                levels.append(r.level)
            mark = f"【{LEVEL_TITLES[r.level]}】" if r.level else ""
            add(("", f"・{mark}{r.label}: {r.message}(記載: {', '.join(r.target.wheres[:3])})\n"))
        sources = sorted({releases.SOURCE_LABELS[r.target.product] for r in f.release_results})
        add(("", f"  公式のリリース情報({'・'.join(sources)})と比べています。古い版は「修正を取り込んでいない」"
                 "という意味で、どの脆弱性の対象かまでは判定していません。\n"))

    # 4. WordPress
    if f.wp_core or f.wp_plugins or f.wp_error:
        add(("h", "\n■ WordPress\n"))
        if f.wp_error:
            levels.append(core.CHECK)
            add(("", f"※WordPress公式の情報に接続できず、確認できませんでした({f.wp_error})。\n"))
        for where, r in f.wp_core:
            levels.append(r.level)
            add(("", f"・【{LEVEL_TITLES[r.level]}】本体({where}): {r.message}\n"))
        for p in sorted(f.wp_plugins, key=lambda p: -LEVEL_RANK[p.level]):
            levels.append(p.level)
            add(("", f"・【{LEVEL_TITLES[p.level]}】プラグイン {p.name} {p.version or ''}: {p.message}\n"))
        if f.wp_plugins:
            add(("", "  ※プラグインは「新しい版が出ているか」「配布停止か」を確認しています。"
                     "古い版の具体的な脆弱性までは照合していません。\n"))

    # 4.5 秘密の鍵の置き方
    if f.leaks is not None:
        add(("h", "\n■ 秘密の鍵(APIキー・パスワード)の置き方\n"))
        if not f.leaks:
            add(("", "漏れそうな置き方は見つかりませんでした(形でわかる鍵だけを探しています)。\n"))
        for lk in f.leaks:
            levels.append(lk.level)
            where = f"{lk.file}" + (f" の{lk.line}行目" if lk.line else "")
            value = f" {lk.masked}" if lk.masked else ""
            add(("", f"・【{LEVEL_TITLES[lk.level]}】{lk.kind}({where}){value}: {lk.reason}\n"))
        add(("", "  ※ファイルの中身はこのPCの中で調べただけで、外には送っていません。\n"))

    # 5. 部品
    if f.scan is not None:
        _package_section(f, findings, unknown, levels, add)

    level = max(levels, key=LEVEL_RANK.get) if levels else core.SAFE
    headline = {core.DANGER: "早めの対応が必要な問題が見つかりました", core.CHECK: "確認が必要な点があります",
                core.SAFE: "問題は見つかりませんでした"}[level]

    add(("h", "\n■ 次にやること\n"))
    if level == core.SAFE:
        add(("", "特に作業は不要です。新しい脆弱性は毎日見つかるので、ときどき診断し直してください。\n"))
        if f.site is not None and f.site.advice:
            add(("", "余裕があれば、「あると安心な設定」を「AIへの修正依頼文をコピー」でAIに頼んでください。\n"))
    else:
        add(("", "1. サイトをAIに作ってもらった場合: 下の「AIへの修正依頼文をコピー」を押して、"
                 "いつも使っているAIに貼り付けてください。\n"
                 "2. 制作会社に作ってもらった場合: 「問い合わせ文をコピー」を押して送ってください。\n"
                 "3. 直したら、もう一度この診断をして【問題は見つからず】になるか確認してください。\n"))
    prevention = _prevention(f, unknown)
    if prevention:
        add(("h", "\n■ 同じことを繰り返さないために\n"))
        for human, _ in prevention:
            add(("", f"・{human}\n"))
    add(("", "\n※この結果は、入力された情報と公開データベースの照合にもとづく目安です。手元のフォルダと"
             "実際に公開されている版が違う場合や、データベースに載っていない脆弱性はわかりません。\n"))
    if f.php_result is not None or f.site_php_result is not None:
        add(("", f"PHP本体の判定に使ったデータ: {f.nvd_source}\n"))

    report = Report(level, headline, lines)
    if level != core.SAFE:
        report.ai_prompt = make_ai_prompt(f, findings, unknown)
        report.inquiry = make_inquiry(f, findings)
    elif (f.site is not None and f.site.advice) or any(ai for _, ai in prevention):
        # 問題は無くても、あると安心な設定・再発防止は AI に頼めるようにする
        report.ai_prompt = make_ai_prompt(f, findings, unknown, safe=True)
    return report


def _prevention(f, unknown):
    """再発防止の案内 [(画面の文章, AIへの依頼文 or "")]。"""
    out = []
    if f.scan is not None and f.scan.packages:
        out.append(("GitHubにプログラムを置いているなら、Dependabot(無料)を有効にすると、部品に脆弱性が見つかった時に"
                    "GitHubが自動で知らせてくれます(リポジトリの Settings → Code security → Dependabot alerts)。",
                    "GitHub の Dependabot alerts を有効にする手順を説明し、依存パッケージの更新を週1回提案させる"
                    ".github/dependabot.yml を追加してください(GitHub を使っていなければ、この項目は不要です)。"))
    if unknown:
        out.append(("AIに「lockファイルは消さずに残して」と頼んでください。正確な版がわかり、診断もできるようになります。",
                    "lockファイル(package-lock.json・composer.lock 等)は今後も git で管理し、削除・無視しないでください。"))
    if f.leaks:
        out.append(("秘密の鍵は、プログラムに直接書かず、.env(git に記録しない設定にしたファイル)に入れるよう、"
                    "AIに毎回伝えてください。",
                    "今後も秘密の値はコードに直接書かず環境変数で扱い、.env は .gitignore に入れてください。"
                    "ブラウザに配られる環境変数(NEXT_PUBLIC_ 等)には秘密の値を入れないでください。"))
    if f.scan is not None or f.site is not None:
        out.append(("下の「週1回、自動で診断する」を使うと、新しい脆弱性が見つかった時だけ知らせます。", ""))
    return out


def _site_section(f, levels, add):
    s = f.site
    if s.techs:
        desc = "、".join(f"{t.name}{' ' + t.version if t.version else ''}" for t in s.techs)
        add(("", f"たぶん {desc} で動いています。\n"))
    else:
        add(("", "何で動いているかは見分けられませんでした(隠している・作りが特殊、など)。\n"))
    host = fingerprint.main_hosting(s)
    if host:
        add(("", f"置き場所: {host.name}。{fingerprint.HOSTING_NOTES[host.kind]}\n"))
    if s.exposed_versions:
        add(("", f"サーバーがソフトのバージョン({', '.join(s.exposed_versions)})を公開しています。攻撃者の下調べに"
                 "使われるので、隠す設定にするのがおすすめです(すぐ危険という意味ではありません)。\n"))
    if s.status >= 400:
        add(("", f"※ページを開いた結果がエラー(HTTP {s.status})でした。URLが合っているか確認してください。\n"))
    for line, level in _https_problems(s):
        levels.append(level)
        add(("", line))
    if s.cert_expires and (s.cert_expires - datetime.date.today()).days > CERT_SOON_DAYS:
        add(("", f"HTTPSの証明書: {s.cert_expires} まで有効です。\n"))
    if s.advice:
        add(("", "あると安心な設定で、まだ無いもの(無くてもすぐ危険ではありません。AIへの修正依頼文に入れています):\n"))
        for _, text in s.advice:
            add(("", f"    ・{text}\n"))
    for line, level in _mismatch(f):
        levels.append(level)
        add(("", line))
    add(("", "※URLからの推定は外れることがあります。\n"))


def _package_section(f, findings, unknown, levels, add):
    scan = f.scan
    add(("h", "\n■ サイトの部品(開発フォルダから)\n"))
    counts = {}
    for p in scan.packages:
        counts[p.ecosystem] = counts.get(p.ecosystem, 0) + 1
    if scan.packages:
        kinds = "・".join(f"{scanners.ECOSYSTEM_LABELS[e]} {n}個" for e, n in counts.items())
        files = ", ".join(scan.files[:6]) + (f" ほか{len(scan.files) - 6}件" if len(scan.files) > 6 else "")
        add(("", f"見つけた部品: {kinds}(読んだファイル: {files})\n"))
    elif not scan.wordpress:
        add(("", "部品の一覧ファイル(package-lock.json・composer.lock・requirements.txt など)が"
                 "見つかりませんでした。フォルダが合っているか確認してください。\n"))
        levels.append(core.CHECK)
    if scan.hostings:
        add(("", "置き場所の手がかり: " + "、".join(f"{n}({src})" for n, _, src in scan.hostings) + "\n"))
    if f.osv_error and scan.packages:
        levels.append(core.CHECK)
        add(("", f"※脆弱性データベース(OSV.dev)で照合できませんでした({f.osv_error})。"
                 "ネットにつないでもう一度試してください。\n"))
    elif scan.packages:
        if not findings:
            add(("", "版がわかる部品からは、既知の脆弱性は見つかりませんでした。\n"))
        elif f.kev_error:
            add(("", f"※実際に攻撃に使われているか(CISA KEV)は確認できませんでした({f.kev_error})。\n"))
        if findings:
            add((HINT, "(▶ の付いた題を押すと、その脆弱性の詳しい内容が開きます)\n"))
        for fd in findings:
            levels.append(fd.level)
            p = fd.package
            role = "開発時だけ使う部品" if p.dev else "本番で使う部品"
            sev = "・".join(f"{osv.SEVERITY_LABELS[s]}{n}件" for s, n in _severity_counts(fd.vulns))
            fix = f"→ {fd.fix_all} 以上に上げると直ります" if fd.fix_all else "→ 直った版がまだ無いものがあります"
            used = "【実際に攻撃に使われています】" if _exploited(fd) else ""
            add(("", f"\n【{LEVEL_TITLES[fd.level]}】{used}{p.name} {p.version}"
                     f"({scanners.ECOSYSTEM_LABELS[p.ecosystem]}・{role})脆弱性 {len(fd.vulns)}件: {sev}\n    {fix}\n"))
            for v in fd.vulns:  # 全部の題を出す。詳しい内容は押した時だけ開く(画面の "fold"/"detail")
                tag = "・攻撃に使われている" if v.exploited else ""
                add((FOLD, f"    ▶ [{osv.SEVERITY_LABELS[v.severity]}{tag}] {v.summary or '(題なし)'}({v.cve or v.id})\n"))
                add((DETAIL, _vuln_detail(v)))
            if p.dev:
                add(("", "    (開発時だけ使う部品は、ふつう公開中のサイトには含まれないので、"
                         "危険度は低めです。次に直す時についでに更新すれば十分です)\n"))
    if unknown:
        levels.append(core.CHECK)
        names = ", ".join(f"{p.name} {p.spec}" for p in unknown[:8]) + (" など" if len(unknown) > 8 else "")
        add(("", f"\n【要確認】版が確定していない部品が {len(unknown)}個あり、照合できませんでした: {names}\n"
                 "    → 部品の一覧ファイル(lockファイル)が無いのが原因です。AIに「lockファイルを作って」と"
                 "頼むと正確に調べられます。\n"))
    for e in scan.errors:
        levels.append(core.CHECK)
        add(("", f"※読めなかったファイル: {e}\n"))


def problem_items(f):
    """前回との比較用に、問題を {ID: 文章} にする。ID は日付など毎回変わるものを含めない。"""
    items = {}
    featured = _featured_php(f)
    if featured and featured[0] in (core.DANGER, core.CHECK):
        items[f"php2shell:{featured[0]}"] = f"PHP2Shell: 【{LEVEL_TITLES[featured[0]]}】{featured[1]}"
    if f.site is not None:
        for line, _ in _https_problems(f.site):
            items["https:" + ("cert" if f.site.https else "none")] = line.strip()
    for r in f.runtime_results:
        if r.level in (core.DANGER, core.CHECK):
            items[f"runtime:{r.product}:{r.cycle}:{r.exact}:{r.level}"] = f"{r.label}: {r.message}"
    for r in f.release_results:
        if r.fix:
            items[f"release:{r.target.product}:{r.target.version}:{r.fix}"] = f"{r.label}: {r.fix} 以上に上げる"
    for where, c in f.wp_core:
        if c.level in (core.DANGER, core.CHECK):
            items[f"wp:{where}:{c.level}"] = f"WordPress本体({where}): {c.message}"
    for p in f.wp_plugins:
        if p.level in (core.DANGER, core.CHECK):
            items[f"plugin:{p.slug}:{p.version}:{p.level}"] = f"WordPressプラグイン {p.name}: {p.message}"
    for fd in package_findings(f.scan.packages, f.vuln_map) if f.scan else []:
        p = fd.package
        for v in fd.vulns:
            label = f"{p.name} {p.version}: {v.summary}({v.cve or v.id})"
            items[f"pkg:{p.ecosystem}:{p.name}:{p.version}:{v.id}"] = label
            if v.exploited:  # KEV に載った(=攻撃に使われ始めた)時も「新しく見つかったもの」にする
                items[f"kev:{p.ecosystem}:{p.name}:{p.version}:{v.id}"] = f"【実際に攻撃に使われています】{label}"
    for lk in f.leaks or []:
        items[f"leak:{lk.file}:{lk.kind}:{lk.level}"] = f"秘密の鍵の置き方: {lk.kind}({lk.file})"
    return items


def is_complete(f):
    """照合できなかったものが無いか(できなかった回は、前回との比較に使わない)。"""
    release_failed = any(r.level == core.CHECK and not r.fix and r.target.version for r in f.release_results)
    return not (f.osv_error or f.wp_error or f.kev_error or f.site_error or release_failed)


def _https_problems(site):
    """HTTPS についての問題 [(文章, 判定)]。"""
    if not site.https:
        return [("【要確認】サイトが暗号化(HTTPS)されていません。入力した内容や Cookie を途中で盗み見られる"
                 "おそれがあります。https:// で開けるようにしてください。\n", core.CHECK)]
    if site.cert_expires:
        days = (site.cert_expires - datetime.date.today()).days
        if days <= CERT_SOON_DAYS:
            return [(f"【要確認】HTTPSの証明書の期限が近づいています({site.cert_expires}、あと{max(days, 0)}日)。"
                     "自動で更新されているか確認してください。切れるとサイトが開けなくなります。\n", core.CHECK)]
    return []


def _mismatch(f):
    """URLから見えた技術と、開発フォルダの部品が食い違っていないか。[(文章, 判定)]"""
    if f.site is None or f.scan is None or not f.scan.packages:
        return []
    out = []
    names = {(p.ecosystem, p.name.lower()) for p in f.scan.packages}
    for t in f.site.techs:
        expected = TECH_PACKAGES.get(t.name)
        if not expected:
            continue
        if expected in names:
            ver = next((p.version for p in f.scan.packages if (p.ecosystem, p.name.lower()) == expected), None)
            out.append((f"開発フォルダにも {expected[1]} {ver or ''} があり、公開中のサイトと一致しているようです。\n",
                        core.SAFE))
        else:
            out.append((f"サイトは {t.name} で動いているようですが、開発フォルダに {expected[1]} が見当たりません。"
                        "違うフォルダを選んでいないか確認してください。\n", core.CHECK))
    return out


def _severity_counts(vulns):
    counts = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    return sorted(counts.items(), key=lambda x: -x[0])


def _php_problem(f):
    for r in (f.php_result, f.site_php_result):
        if r is not None and r.level in (core.DANGER, core.CHECK):
            return r
    return None


def make_ai_prompt(f, findings, unknown, safe=False):
    out = []
    target = f"(フォルダ: {f.folder})" if f.folder else ""
    site = f"(公開URL: {f.url})" if f.url else ""
    if safe:
        out.append(f"このプロジェクト{target}{site}の安全性を確認したところ、大きな問題は見つかりませんでしたが、"
                   "今後のために次の点を対応してください。")
    else:
        out.append(f"このプロジェクト{target}{site}の安全性を確認したところ、次の問題が見つかりました。")
    if _php_problem(f):
        out.append("- サーバーのPHPがPHP2Shell(CVE-2026-109618 / CVE-2026-109619)の対象の可能性があります。"
                   "PHPを 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 以降(使っている系列の修正版)に更新する方法を調べ、"
                   "手順を説明してください。")
    for r in f.runtime_results:
        if r.level in (core.DANGER, core.CHECK):
            out.append(f"- {r.label}: {r.message}(記載: {', '.join(r.sources[:3])})。"
                       "サポート中の版に上げる場合の影響と手順を説明してください。")
    if f.leaks:
        out.append("- 【最優先】秘密の鍵(APIキー等)が漏れそうな置き方をしています。鍵はサーバー側の環境変数に移し、"
                   "ブラウザに配られるコード・git の記録に入らないようにしてください。すでに GitHub や公開中のサイトに"
                   "出ていた鍵は、各サービスの管理画面で作り直す(古い鍵を無効にする)手順も説明してください:")
        out += [f"  - {lk.kind}({lk.file}" + (f" {lk.line}行目" if lk.line else "") + f"): {lk.reason}"
                for lk in f.leaks]
    for r in f.release_results:
        if r.fix:
            out.append(f"- {r.label}(記載: {', '.join(r.target.wheres[:3])}): 公式の修正版 {r.fix} 以上に"
                       "更新してください。サーバー・Docker イメージ・バージョン指定ファイルのどこを直せばよいかも"
                       "説明してください。")
    for where, r in f.wp_core:
        if r.level in (core.DANGER, core.CHECK):
            out.append(f"- WordPress本体({where}): {r.message}")
    for p in f.wp_plugins:
        if p.level in (core.DANGER, core.CHECK):
            out.append(f"- WordPressプラグイン {p.slug} {p.version or ''}: {p.message}")
    if f.site is not None and f.site.exposed_versions:
        out.append(f"- Webサーバーがバージョン({', '.join(f.site.exposed_versions)})を応答ヘッダで公開しています。"
                   "公開しない設定にしてください。")
    if f.site is not None:
        for line, _ in _https_problems(f.site):
            out.append("- " + line.removeprefix("【要確認】").strip())
        if f.site.advice:
            out.append("- 公開中のサイトの応答に、次のセキュリティ用の設定がありません。サイトの動きを壊さない範囲で"
                       "追加してください(特に CSP は、許可するものを確認しながら段階的に):")
            out += [f"  - {text}" for _, text in f.site.advice]
    if findings:
        out.append("- 次の依存パッケージに既知の脆弱性があります。記載の版以上に更新してください。")
        for fd in findings:
            p = fd.package
            ids = ", ".join(v.cve or v.id for v in fd.vulns[:5]) + (" ほか" if len(fd.vulns) > 5 else "")
            goal = f"{fd.fix_all} 以上" if fd.fix_all else "修正版が無い脆弱性を含むため、代替手段を提案"
            role = "開発時のみ" if p.dev else "本番依存"
            urgent = "【最優先: 実際に攻撃に使われている脆弱性あり(CISA KEV)】" if _exploited(fd) else ""
            out.append(f"  - {urgent}[{p.ecosystem}] {p.name} {p.version} → {goal}({role} / {ids} / 記載: {p.source})")
    if unknown:
        out.append(f"- lockファイルが無く、{len(unknown)}個の依存パッケージの実際の版を確認できませんでした。"
                   "lockファイルを作成(npm install / composer update --lock / pip freeze 等)してください。")
    later = [ai for _, ai in _prevention(f, unknown) if ai]
    if later:
        out += ["", "再発防止のため、次も対応してください:"] + [f"- {ai}" for ai in later]
    out += ["", "進め方の希望:",
            "1. lockファイルも更新される方法で更新する(依存パッケージを直接編集しない)",
            "2. メジャーバージョンが上がるものは、破壊的変更の有無を先に調べて説明する",
            "3. 更新後にビルド・テスト・起動確認を行い、結果を報告する",
            "4. 本番(公開中のサイト)へ反映する前に、変更内容を説明して確認を取る"]
    return "\n".join(out)


def make_inquiry(f, findings):
    url = f"({f.url})" if f.url else ""
    out = ["お世話になっております。", f"当方のサイト{url}の安全性を診断ツールで確認したところ、次の点が見つかりました。"]
    r = _php_problem(f)
    if r is not None:
        out.append(f"・サーバーのPHP({r.version_text})が、2026年10月21日に修正されたPHPの脆弱性"
                   "(PHP2Shell、CVE-2026-109618 / CVE-2026-109619)の対象の可能性があります。")
    for rt in f.runtime_results:
        if rt.level in (core.DANGER, core.CHECK):
            out.append(f"・{rt.label}: {rt.message}")
    for r in f.release_results:
        if r.fix:
            out.append(f"・{r.label}: 公式の修正版 {r.fix} が出ていますが、まだ取り込まれていないようです。")
    for _, c in f.wp_core:
        if c.level in (core.DANGER, core.CHECK):
            out.append(f"・WordPress本体: {c.message}")
    for p in f.wp_plugins:
        if p.level in (core.DANGER, core.CHECK):
            out.append(f"・WordPressのプラグイン {p.name}: {p.message}")
    for fd in findings:
        ids = ", ".join(v.cve or v.id for v in fd.vulns[:3])
        used = "(うち実際に攻撃に使われているものあり)" if _exploited(fd) else ""
        out.append(f"・部品 {fd.package.name} {fd.package.version} に既知の脆弱性({ids} など{len(fd.vulns)}件){used}")
    for lk in f.leaks or []:
        out.append(f"・秘密の鍵の置き方: {lk.kind}({lk.file}): {lk.reason}")
    out += ["影響の有無と、対応の予定(更新の時期・サイトへの影響)を教えてください。", "よろしくお願いいたします。"]
    return "\n".join(out)


def to_text(report, f, when=None):
    """「結果を保存」用のテキスト。"""
    when = when or datetime.datetime.now()
    head = [f"{APP_NAME} v{APP_VERSION} 診断結果", f"診断日時: {when:%Y-%m-%d %H:%M}",
            f"サイトのURL: {f.url or '(入力なし)'}", f"開発フォルダ: {f.folder or '(入力なし)'}",
            f"PHPのバージョン: {f.php_text or '(入力なし)'}", "",
            f"判定: {LEVEL_TITLES[report.level]} — {report.headline}", "", ""]
    # 保存するテキストには、閉じている詳しい内容も全部入れる
    body = "".join(text.replace("▶", "・", 1) if tag == FOLD else text
                   for tag, text in report.lines if tag != HINT)
    tail = []
    if report.ai_prompt:
        tail += ["", "=" * 16 + " AIへの修正依頼文 " + "=" * 16, report.ai_prompt]
    if report.inquiry:
        tail += ["", "=" * 16 + " 問い合わせ文 " + "=" * 16, report.inquiry]
    return "\n".join(head) + body + "\n".join(tail) + "\n"
