"""画面(tkinter)。材料集めと判定は diagnose / report に任せる。"""

import datetime
import os
import threading
import tkinter as tk
import sys
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import APP_NAME, APP_VERSION, core, detect, diagnose, history, notices, report, schedule

FONT = "Yu Gothic UI"
LEVEL_COLORS = {
    core.DANGER: "#c62828",
    core.CHECK: "#e65100",
    core.SAFE: "#2e7d32",
    core.INPUT_ERROR: "#555555",
}
LEVEL_TITLES = report.LEVEL_TITLES

SERVER_CHOICES = [
    (core.SERVER_UNKNOWN, "サーバーの種類: わからない"),
    (core.SERVER_RENTAL, "サーバーの種類: レンタルサーバー"),
    (core.SERVER_SELF, "サーバーの種類: 自分で管理(VPS・クラウド等)"),
]

HOWTO_TEXT = """\
■ WordPress のサイトの場合(いちばん簡単)
  1. WordPress の管理画面にログインする
  2. 左のメニューの「ツール」→「サイトヘルス」を開く
  3. 上の「情報」タブ →「サーバー」を開く
  4. 「PHP バージョン」に書かれている数字(例: 8.3.12)を入力する

■ レンタルサーバーの場合
  サーバーの管理画面(サーバーパネル・コントロールパネル)に
  「PHP バージョン」「PHP Ver.切替」などの項目があります。
  ※ 「8.3」までしか表示されない場合は、サーバー会社のお知らせで
    修正版に更新済みかを確認してください。

■ 自分で管理しているサーバーの場合
  サーバーに入って  php -v  を実行すると最初の行に表示されます。
  ※ Web で動いている PHP と、コマンドの PHP が別の版のこともあります。
    確実なのは、サイトの管理画面や phpinfo() で確認する方法です
    (phpinfo() のページは確認後すぐに削除してください)。

■ どれもわからない場合
  サイトを作った制作会社に「PHP のバージョンを教えてください」と聞いてください。
"""


class App:
    def __init__(self, root):
        self.root = root
        self.state = diagnose.State()
        self.result = None
        self.findings = None
        self.found = None  # 自動検出で入れた版(detect.Finding)。手で書き換えたら使わない

        root.title(f"{APP_NAME} v{APP_VERSION}")
        root.geometry("860x900")
        root.minsize(680, 640)

        style = ttk.Style(root)
        style.configure(".", font=(FONT, 10))
        style.configure("Head.TLabel", font=(FONT, 15, "bold"))
        style.configure("Step.TLabelframe.Label", font=(FONT, 11, "bold"))
        style.configure("Big.TButton", font=(FONT, 12, "bold"), padding=8)

        menubar = tk.Menu(root)
        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="調べられること・調べられないこと",
                              command=lambda: self.show_text("調べられること・調べられないこと", notices.SCOPE_TEXT))
        help_menu.add_command(label="免責事項", command=lambda: self.show_text("免責事項", notices.DISCLAIMER_TEXT))
        help_menu.add_command(label="警告が出た時(署名と除外の設定)", command=self.show_warning_help)
        help_menu.add_separator()
        help_menu.add_command(label="バージョン情報", command=lambda: messagebox.showinfo(
            "バージョン情報", notices.about_text(), parent=self.root))
        menubar.add_cascade(label="ヘルプ", menu=help_menu)
        root.configure(menu=menubar)

        outer = ttk.Frame(root, padding=14)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_NAME, style="Head.TLabel").pack(anchor="w")
        ttk.Label(outer, wraplength=800, justify="left", text=(
            "AIや制作会社に作ってもらったサイトに、既知の脆弱性(セキュリティの穴)が無いかを調べます。"
            "わかるものだけ入れてください。ソースコードやファイルの中身は外部に送りません。"
        )).pack(anchor="w", pady=(2, 8))

        # ① URL
        f1 = ttk.LabelFrame(outer, text="① サイトのURL(自分のサイトだけに使ってください)", style="Step.TLabelframe",
                            padding=8)
        f1.pack(fill="x")
        self.url = tk.StringVar()
        url_entry = ttk.Entry(f1, textvariable=self.url, width=50)
        url_entry.pack(side="left")
        url_entry.bind("<Return>", lambda _e: self.run_check())
        ttk.Label(f1, text="  例: https://example.com(ページを1回開くだけです)",
                  foreground="#777777").pack(side="left")

        # ② 開発フォルダ
        f2 = ttk.LabelFrame(outer, text="② 開発フォルダ(AIが作ったプログラムが入っているフォルダ)",
                            style="Step.TLabelframe", padding=8)
        f2.pack(fill="x", pady=(8, 0))
        self.folder = tk.StringVar()
        ttk.Entry(f2, textvariable=self.folder, width=62).pack(side="left", fill="x", expand=True)
        ttk.Button(f2, text="選ぶ", command=self.choose_folder).pack(side="left", padx=(6, 0))

        # ③ PHP のバージョン
        f3 = ttk.LabelFrame(outer, text="③ サーバーのPHPのバージョン(わかる人だけ)", style="Step.TLabelframe",
                            padding=8)
        f3.pack(fill="x", pady=(8, 0))
        row = ttk.Frame(f3)
        row.pack(fill="x")
        self.version = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.version, width=22, font=(FONT, 11))
        entry.pack(side="left")
        entry.bind("<Return>", lambda _e: self.run_check())
        self.server = ttk.Combobox(row, state="readonly", width=34, values=[label for _, label in SERVER_CHOICES])
        self.server.current(0)
        self.server.pack(side="left", padx=6)
        ttk.Button(row, text="調べ方", command=self.show_howto).pack(side="right")
        ttk.Button(row, text="開発環境から自動で調べる", command=self.show_detect).pack(side="right", padx=(0, 6))

        self.use_online = tk.BooleanVar(value=True)
        ttk.Checkbutton(outer, variable=self.use_online, text=(
            "ネットの最新情報で照合する(OSV.dev・NVD・各公式サイト等。送るのは部品の名前・版などで、ファイルの中身は送りません)")).pack(anchor="w", pady=(8, 0))

        self.check_button = ttk.Button(outer, text="診断する", style="Big.TButton", command=self.run_check)
        self.check_button.pack(fill="x", pady=8)

        # 下の段は結果欄より先に配置する(窓が小さくても隠れないように)
        bottom = ttk.Frame(outer)
        bottom.pack(side="bottom", fill="x", pady=(6, 0))
        self.ai_button = ttk.Button(bottom, text="AIへの修正依頼文をコピー", width=24, state="disabled",
                                    command=lambda: self.copy("ai_prompt", self.ai_button))
        self.ai_button.pack(side="left")
        self.inquiry_button = ttk.Button(bottom, text="問い合わせ文をコピー", width=20, state="disabled",
                                         command=lambda: self.copy("inquiry", self.inquiry_button))
        self.inquiry_button.pack(side="left", padx=(6, 0))
        self.save_button = ttk.Button(bottom, text="結果を保存", width=12, state="disabled", command=self.save)
        self.save_button.pack(side="left", padx=(6, 0))
        self.schedule_button = ttk.Button(bottom, text="", command=self.toggle_schedule)
        self.schedule_button.pack(side="right")
        self._update_schedule_button()
        self.status = ttk.Label(bottom, text="", foreground="#555555")
        self.status.pack(side="left", padx=(12, 0))

        self.level_label = tk.Label(outer, text="", font=(FONT, 16, "bold"), fg="white", bg="#ffffff",
                                    anchor="w", padx=10, pady=6)
        self.level_label.pack(fill="x")
        # wrap="char": "word" だと日本語の文中の空白(「置き場所: Caddy」等)で早すぎる改行が起きる
        self.output = ScrolledText(outer, wrap="char", font=(FONT, 10), height=8, relief="solid", borderwidth=1)
        self.output.pack(fill="both", expand=True)
        self.output.tag_configure("h", font=(FONT, 11, "bold"))
        # 脆弱性の題(押すと詳しい内容が開く・閉じる)
        self.output.tag_configure(report.FOLD, foreground="#1a56a8")
        self.output.tag_configure(report.DETAIL, foreground="#444444", background="#f4f6fa")
        self.output.tag_bind(report.FOLD, "<Button-1>", self._toggle_fold)
        self.output.tag_bind(report.FOLD, "<Enter>", lambda _e: self.output.configure(cursor="hand2"))
        self.output.tag_bind(report.FOLD, "<Leave>", lambda _e: self.output.configure(cursor=""))
        self._write_lines([("", "ここに診断結果が表示されます。")])

    # --- 操作 ---
    def choose_folder(self):
        path = filedialog.askdirectory(parent=self.root, title="開発フォルダを選んでください")
        if path:
            self.folder.set(os.path.normpath(path))

    def server_type(self):
        return SERVER_CHOICES[max(self.server.current(), 0)][0]

    def run_check(self):
        folder = self.folder.get().strip()
        if folder and not os.path.isdir(folder):
            self._show(report.Report(core.INPUT_ERROR, "開発フォルダが見つかりません",
                                     [("", f"「{folder}」というフォルダはありません。「選ぶ」で選び直してください。")]))
            return
        self.check_button.configure(state="disabled", text="診断しています…(部品が多いと少し時間がかかります)")
        args = (self.url.get(), folder, self.version.get(), self.server_type(), self.use_online.get())
        threading.Thread(target=self._work, args=args, daemon=True).start()

    def _work(self, url, folder, version_text, server_type, online):
        """別スレッドで、材料集め・照合・判定をする(画面を固めない)。"""
        findings = None
        try:
            findings, result = diagnose.run(url, folder, version_text, server_type, online, self.state, self.found,
                                            history.default_path())
        except Exception as e:  # 想定外のエラーでも画面を止めない
            result = report.Report(core.INPUT_ERROR, "診断中にエラーが起きました",
                                   [("", f"{type(e).__name__}: {e}\n")])
        self.root.after(0, self._show, result, findings)

    def _show(self, result, findings=None):
        self.check_button.configure(state="normal", text="診断する")
        self.result, self.findings = result, findings
        self.level_label.configure(text=f" 判定: {LEVEL_TITLES[result.level]} — {result.headline}",
                                   bg=LEVEL_COLORS[result.level])
        self._write_lines(result.lines)
        self.ai_button.configure(state="normal" if result.ai_prompt else "disabled", text="AIへの修正依頼文をコピー")
        self.inquiry_button.configure(state="normal" if result.inquiry else "disabled", text="問い合わせ文をコピー")
        can_save = findings is not None and result.level != core.INPUT_ERROR
        self.save_button.configure(state="normal" if can_save else "disabled", text="結果を保存")
        self.status.configure(text="")

    def save(self):
        name = f"診断結果_{datetime.datetime.now():%Y%m%d_%H%M}.txt"
        path = filedialog.asksaveasfilename(parent=self.root, title="結果を保存", initialfile=name,
                                            defaultextension=".txt", filetypes=[("テキスト", "*.txt")])
        if path:
            self.write_report(path)

    def write_report(self, path):
        # メモ帳等で文字化けしないよう BOM 付き UTF-8 で書く
        with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:
            f.write(report.to_text(self.result, self.findings))
        self.save_button.configure(text="保存しました")

    def copy(self, attr, button):
        self.root.clipboard_clear()
        self.root.clipboard_append(getattr(self.result, attr))
        button.configure(text="コピーしました")

    def _update_schedule_button(self):
        self.scheduled = schedule.is_registered()
        self.schedule_button.configure(text="週1回の自動診断を止める" if self.scheduled else "週1回、自動で診断する")

    def toggle_schedule(self):
        if self.scheduled:
            ok, err = schedule.unregister()
            if ok:
                messagebox.showinfo("自動診断", "週1回の自動診断を止めました。", parent=self.root)
            else:
                messagebox.showerror("自動診断", f"止められませんでした。\n{err}", parent=self.root)
            self._update_schedule_button()
            return
        url, folder, version = self.url.get().strip(), self.folder.get().strip(), self.version.get().strip()
        if not (url or folder or version):
            messagebox.showinfo("自動診断", "先に①〜③のどれかを入れてください。今の入力で毎週診断します。",
                                parent=self.root)
            return
        visit = "\n・①のサイトは、そのたびに1回開きます。" if url else ""
        if not messagebox.askokcancel("自動診断", (
                "今の入力(①〜③)で、毎週月曜の10時に自動で診断します。\n"
                "・その時間にPCが切れていたら、次に起動した時に診断します。\n"
                "・前回から新しく見つかった問題がある時だけ、この窓が開いてお知らせします。"
                f"{visit}\n・Windows のタスクスケジューラに「{schedule.TASK_NAME}」として登録します。\n\n"
                "登録してよいですか?"), parent=self.root):
            return
        schedule.save_settings(url, folder, version, self.server_type())
        ok, err = schedule.register()
        if ok:
            messagebox.showinfo("自動診断", "登録しました。止める時は「週1回の自動診断を止める」を押してください。",
                                parent=self.root)
        else:
            messagebox.showerror("自動診断", f"登録できませんでした。\n{err}", parent=self.root)
        self._update_schedule_button()

    def load_auto_result(self, settings, findings, result):
        """自動診断で新しい問題が見つかった時に、その結果を入力欄ごと表示する。"""
        self.url.set(settings.get("url", ""))
        self.folder.set(settings.get("folder", ""))
        self.version.set(settings.get("php_text", ""))
        codes = [code for code, _ in SERVER_CHOICES]
        self.server.current(codes.index(settings["server_type"]) if settings.get("server_type") in codes else 0)
        self.root.title(f"{APP_NAME} v{APP_VERSION} — 自動診断で新しい問題が見つかりました")
        self._show(result, findings)

    def show_text(self, title, body, width=720, height=600):
        """読むだけの文章の窓。開いた窓を返す(テスト用)。"""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry(f"{width}x{height}")
        win.transient(self.root)
        text = ScrolledText(win, wrap="char", font=(FONT, 10), padx=10, pady=10)
        ttk.Button(win, text="閉じる", command=win.destroy).pack(side="bottom", pady=6)
        text.pack(fill="both", expand=True)
        text.insert("1.0", body)
        text.configure(state="disabled")
        win.text = text
        return win

    def show_warning_help(self):
        win = self.show_text("警告が出た時(署名と除外の設定)", notices.WARNING_TEXT + "\n■ このファイルの SHA-256\n  計算しています…\n",
                             height=680)

        def work():
            try:
                digest = notices.self_sha256() or "(開発中の起動のため、表示しません。exe で起動すると表示されます)"
            except OSError as e:
                digest = f"(計算できませんでした: {type(e).__name__})"
            self.root.after(0, lambda: show(digest))

        def show(digest):
            if not win.winfo_exists():
                return
            win.text.configure(state="normal")
            start = win.text.search("計算しています…", "1.0")
            if start:
                win.text.delete(start, f"{start} lineend")
                win.text.insert(start, digest)
            win.text.configure(state="disabled")
        threading.Thread(target=work, daemon=True).start()  # 11MB ほど読むので画面を固めない
        return win

    def show_howto(self):
        win = tk.Toplevel(self.root)
        win.title("PHP のバージョンの調べ方")
        win.geometry("640x520")
        text = ScrolledText(win, wrap="word", font=(FONT, 10), padx=8, pady=8)
        text.pack(fill="both", expand=True)
        text.insert("1.0", HOWTO_TEXT)
        text.configure(state="disabled")
        ttk.Button(win, text="閉じる", command=win.destroy).pack(pady=6)

    def show_detect(self):
        DetectDialog(self)

    def use_finding(self, finding):
        """自動検出の結果を入力欄に入れて、そのまま診断する。"""
        self.found = finding
        self.version.set(finding.version)
        self.run_check()

    # --- 表示の下請け ---
    def _write_lines(self, lines):
        out = self.output
        out.configure(state="normal")
        out.delete("1.0", "end")
        for name in out.tag_names():  # 前回の結果の開け閉め用の印を消す
            if name.startswith(("fold#", "detail#")):
                out.tag_delete(name)
        n = 0
        for tag, text in lines:
            if tag == report.FOLD:
                n += 1
                out.insert("end", text, (report.FOLD, f"fold#{n}"))
            elif tag == report.DETAIL:
                out.tag_configure(f"detail#{n}", elide=True)  # 最初は閉じておく
                out.insert("end", text, (report.DETAIL, f"detail#{n}"))
            else:
                out.insert("end", text, tag or ())
        out.configure(state="disabled")

    def _toggle_fold(self, event):
        out = self.output
        name = next((t for t in out.tag_names(f"@{event.x},{event.y}") if t.startswith("fold#")), None)
        if name is None:
            return
        detail = "detail#" + name.split("#")[1]
        opening = str(out.tag_cget(detail, "elide")).lower() in ("1", "true")  # 今閉じている → 開く
        out.configure(state="normal")
        out.tag_configure(detail, elide=not opening)
        start = out.tag_ranges(name)[0]
        arrow = out.search("▼" if not opening else "▶", start, f"{start} lineend")
        if arrow:  # 印も ▶(閉) ⇔ ▼(開) に変える
            out.delete(arrow)
            out.insert(arrow, "▼" if opening else "▶", (report.FOLD, name))
        out.configure(state="disabled")


class DetectDialog:
    """開発環境から PHP の版を探す窓。"""

    def __init__(self, app):
        self.app = app
        self.findings = []
        self.win = win = tk.Toplevel(app.root)
        win.title("開発環境から自動で調べる")
        win.geometry("760x560")
        win.transient(app.root)

        body = ttk.Frame(win, padding=12)
        body.pack(fill="both", expand=True)
        ttk.Label(body, wraplength=720, justify="left", text=(
            # tk は空白でしか折り返さないので、日本語の文中に空白を入れない(変な位置で改行される)
            "このPCに入っているPHP(XAMPP・Laragon・WAMP・MAMPなど)と、動いているDockerのコンテナから"
            "PHPのバージョンを探します。調べるだけで、何も変更しません。\n"
            "※ 開発環境のバージョンは、本番サイト(レンタルサーバー等)と違うことがあります。"
        )).pack(anchor="w")

        self.scan_button = ttk.Button(body, text="このPCとDockerを調べる", style="Big.TButton", command=self.scan)
        self.scan_button.pack(fill="x", pady=(10, 4))

        url_box = ttk.LabelFrame(body, text="詳しい人向け: 開発用サイトのURLから調べる(このPC・社内LANのアドレスのみ)",
                                 padding=8)
        url_box.pack(fill="x", pady=(6, 4))
        self.url = tk.StringVar(value="http://localhost:8000")
        url_entry = ttk.Entry(url_box, textvariable=self.url, width=50)
        url_entry.pack(side="left")
        url_entry.bind("<Return>", lambda _e: self.check_url())
        self.url_button = ttk.Button(url_box, text="調べる", command=self.check_url)
        self.url_button.pack(side="left", padx=6)

        self.message = ttk.Label(body, text="", wraplength=720, justify="left")
        self.message.pack(anchor="w", pady=(4, 4))

        self.tree = ttk.Treeview(body, columns=("kind", "version", "place"), show="headings", height=8)
        for col, label, width in (("kind", "見つけた場所", 110), ("version", "バージョン", 170), ("place", "詳細", 440)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.use_button.configure(state="normal"))
        self.tree.bind("<Double-1>", lambda _e: self.use_selected())

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(8, 0))
        self.use_button = ttk.Button(buttons, text="選んだバージョンで診断する", command=self.use_selected,
                                     state="disabled")
        self.use_button.pack(side="left")
        ttk.Button(buttons, text="閉じる", command=win.destroy).pack(side="right")

    def scan(self):
        self.scan_button.configure(state="disabled", text="調べています…(少し時間がかかります)")
        self.message.configure(text="")
        threading.Thread(target=self._scan_work, daemon=True).start()

    def _scan_work(self):
        found = []
        for finder in (detect.find_local, detect.find_docker):
            try:  # 片方が想定外のエラーでも、もう片方の結果は出す
                found += finder()
            except Exception:
                pass
        self._done_scan(found)

    def _done_scan(self, found):
        def update():
            if not self.win.winfo_exists():
                return
            self.scan_button.configure(state="normal", text="このPCとDockerを調べる")
            self._add(found)
            self.message.configure(text=(
                f"{len(found)} 件見つかりました。診断したいものを選んでください。" if found else
                "このPCとDockerではPHPが見つかりませんでした。"
                "サイトの管理画面などで調べる方法は「調べ方」を見てください。"))
        self.app.root.after(0, update)

    def check_url(self):
        url = self.url.get()
        self.url_button.configure(state="disabled")
        self.message.configure(text="")

        def work():
            try:
                found, error = detect.check_url(url), None
            except ValueError as e:
                found, error = None, str(e)
            self.app.root.after(0, lambda: self._done_url(found, error))
        threading.Thread(target=work, daemon=True).start()

    def _done_url(self, found, error):
        if not self.win.winfo_exists():
            return
        self.url_button.configure(state="normal")
        if found:
            self._add([found])
            self.message.configure(text="サイトの応答からバージョンが見つかりました。")
        else:
            self.message.configure(text=error)

    def _add(self, found):
        for f in found:
            if any((f.kind, f.place) == (x.kind, x.place) for x in self.findings):
                continue
            self.findings.append(f)
            self.tree.insert("", "end", iid=str(len(self.findings) - 1), values=(f.kind, f.version, f.place))

    def use_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        finding = self.findings[int(selected[0])]
        self.win.destroy()
        self.app.use_finding(finding)


def should_notify(findings, result):
    """自動診断で窓を出すか。前回から新しく見つかった問題がある時(前回が無ければ、危険な時)だけ。"""
    if findings.changes is not None:
        return bool(findings.changes.new)
    return result.level == core.DANGER


def auto_check():
    """(設定, Findings, Report) を返す。窓を出さなくてよければ None。"""
    settings = schedule.load_settings()
    if not settings:
        return None
    try:
        findings, result = diagnose.run(settings.get("url", ""), settings.get("folder", ""),
                                        settings.get("php_text", ""), settings.get("server_type", core.SERVER_UNKNOWN),
                                        True, history_path=history.default_path())
    except Exception:  # 自動診断の失敗では窓を出さない(次の週にまた試す)
        return None
    return (settings, findings, result) if should_notify(findings, result) else None


def main():
    try:  # 高DPI画面で文字がぼやけないようにする(Windowsのみ)
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    auto = None
    if schedule.AUTO_ARG in sys.argv:
        auto = auto_check()
        if auto is None:
            return
    root = tk.Tk()
    app = App(root)
    if auto:
        root.geometry("+40+10")  # 自動で開く時は、下の段のボタンがタスクバーに隠れないよう上に寄せる
        app.load_auto_result(*auto)
        root.attributes("-topmost", True)  # 他の窓の後ろに隠れないように、最初だけ一番前に出す
        root.after(1500, lambda: root.attributes("-topmost", False))
    root.mainloop()
