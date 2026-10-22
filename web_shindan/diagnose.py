"""入力(URL・開発フォルダ・PHPの版)から材料を集めて、診断結果を作る。画面からもテストからも呼ぶ。"""

from dataclasses import dataclass, field

from . import core, data, fingerprint, history, kev, leaks, nvd, osv, releases, report, runtimes, scanners, wordpress


@dataclass
class State:
    """1回の起動の間だけ使い回すデータ(通信を減らすため)。"""
    cves: list = field(default_factory=lambda: data.WATCHED_CVES)
    nvd_source: str = f"内蔵データ({data.SNAPSHOT_DATE} 時点)"
    nvd_fetched: bool = False
    eol_table: dict | None = None
    eol_source: str = ""
    wp_statuses: dict | None = None
    release_tables: dict = field(default_factory=dict)   # {(製品, 大きい方の番号 or ""): {系列: Release}}
    kev: set | None = None


def run(url="", folder="", php_text="", server_type=core.SERVER_UNKNOWN, online=True, state=None, found=None,
        history_path=None):
    """found: 自動検出で入れたPHPの版(detect.Finding)。入力値と一致する時だけ注記に使う。
    history_path: 渡すと前回の結果と比べ、今回の結果を保存する(画面・定期診断から使う)。
    """
    f, result = _collect(url, folder, php_text, server_type, online, state, found)
    # ネットで照合できなかった回は、部品などが「直った」ように見えてしまうので比べない・保存しない
    if history_path and online and result.level != core.INPUT_ERROR and report.is_complete(f):
        key = history.key_of(f.url, f.folder, f.php_text)
        items = report.problem_items(f)
        try:
            f.changes = history.compare(history_path, key, items)
            result = report.build_report(f)
            history.save(history_path, key, items, result.level)
        except OSError:  # 保存できなくても診断の結果は出す
            pass
    return f, result


def _collect(url, folder, php_text, server_type, online, state, found):
    state = state or State()
    f = report.Findings(url=url.strip(), folder=folder.strip(), php_text=php_text.strip())

    if online and (f.php_text or f.url) and not state.nvd_fetched:
        try:
            state.cves = nvd.load_latest(data.WATCHED_CVES)
            state.nvd_fetched, state.nvd_source = True, "NVD の最新情報"
        except Exception as e:  # 通信失敗・形式変更などはすべて内蔵データで判定する
            state.nvd_source = f"内蔵データ({data.SNAPSHOT_DATE} 時点。NVDに接続できず: {type(e).__name__})"
    f.nvd_source = state.nvd_source

    # ③ PHPの版
    if f.php_text:
        found_in = f"{found.kind}: {found.place}" if found and found.version == f.php_text else None
        f.php_result = core.judge(f.php_text, server_type, state.cves, found_in)

    # ① サイトのURL
    if f.url:
        try:
            f.site = fingerprint.check_site(f.url)
        except ValueError as e:  # UrlNotAllowed を含む
            f.site_error = str(e)
        if f.site is not None and f.site.php_version:
            f.site_php_result = core.judge(f.site.php_version, server_type, state.cves, "サイトの応答")

    # ② 開発フォルダ
    if f.folder:
        f.scan = scanners.scan_folder(f.folder)
        f.leaks = leaks.scan(f.folder)  # このPCの中で読むだけ。外には送らない
        if f.scan.packages:
            if online:
                try:
                    f.vuln_map = osv.check_packages(f.scan.packages)
                except Exception as e:
                    f.osv_error = type(e).__name__
            else:
                f.osv_error = "ネットの照合をオフにしています"
        if f.scan.runtimes:
            f.runtime_results = runtimes.check_all(f.scan.runtimes, _eol_table(state, online))
            f.runtime_source = state.eol_source
        if f.vuln_map:
            _mark_exploited(f, state, online)

    # PHP・Node.js・Go の本体が、公式の最新の修正版より古くないか
    php_inputs = [("③に入れた版", f.php_text)] if f.php_text else []
    if f.site is not None and f.site.php_version:
        php_inputs.append(("サイトの応答", f.site.php_version))
    targets = releases.collect(php_inputs, f.scan.runtimes if f.scan else [], server_type == core.SERVER_SELF)
    if targets:
        eol = _eol_table(state, online)
        # サポートが終わった系列は修正版が出ないので比べない(サポート期限・PHP2Shell の判定で扱う)
        targets = [t for t in targets if not runtimes.is_expired(t.product, t.cycle, eol)]
        f.release_results = [_check_release(t, state, online) for t in targets]

    # WordPress(フォルダの本体・プラグイン + サイトの応答に出ていた版)
    wp_targets = [("開発フォルダ" if w.root == "." else f"開発フォルダの {w.root}", w.version)
                  for w in (f.scan.wordpress if f.scan else [])]
    plugins = [p for w in (f.scan.wordpress if f.scan else []) for p in w.plugins]
    if f.site is not None and f.site.tech("WordPress") and f.site.tech("WordPress").version:
        wp_targets.append(("サイトの応答", f.site.tech("WordPress").version))
    if wp_targets or plugins:
        if not online:
            f.wp_error = "ネットの照合をオフにしています"
        else:
            try:
                if state.wp_statuses is None:
                    state.wp_statuses = wordpress.load_core_statuses()
                f.wp_core = [(where, wordpress.check_core(v, state.wp_statuses)) for where, v in wp_targets]
            except Exception as e:
                f.wp_error = type(e).__name__
            if plugins:
                f.wp_plugins = wordpress.check_plugins(plugins)

    return f, report.build_report(f)


def _eol_table(state, online):
    if state.eol_table is None:
        try:
            if not online:
                raise OSError("offline")
            state.eol_table, state.eol_source = runtimes.load_table(), "endoflife.date の最新情報"
        except Exception:
            state.eol_table = runtimes.snapshot_table()
            state.eol_source = f"内蔵データ({data.EOL_SNAPSHOT_DATE} 時点)"
    return state.eol_table


def _check_release(target, state, online):
    major = target.cycle.split(".")[0] if target.product == "php" else ""
    key = (target.product, major)
    if not online:
        return releases.check(target, None, "ネットの照合をオフにしています")
    if key not in state.release_tables:
        try:
            state.release_tables[key] = releases.load(target.product, [major] if major else [])
        except Exception as e:  # 失敗は覚えず、次の診断でもう一度試す
            return releases.check(target, None, f"{releases.SOURCE_LABELS[target.product]} に接続できず: "
                                                f"{type(e).__name__}")
    return releases.check(target, state.release_tables[key])


def _mark_exploited(f, state, online):
    if not online:
        return
    if state.kev is None:
        try:
            state.kev = kev.load()
        except Exception as e:
            f.kev_error = type(e).__name__
            return
    kev.mark(f.vuln_map, state.kev)
