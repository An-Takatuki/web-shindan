"""開発フォルダから、使っている部品(依存パッケージ)と版・実行環境・置き場所・WordPressを拾う。

読むのは部品の一覧ファイル(lockファイル等)・設定ファイル・WordPressの版の記載だけで、ソースコードは読まない。
"""

import json
import os
import re
import tomllib
from dataclasses import dataclass, field

NPM = "npm"
PACKAGIST = "Packagist"
PYPI = "PyPI"
RUBYGEMS = "RubyGems"
GO = "Go"
CRATES = "crates.io"

ECOSYSTEM_LABELS = {NPM: "Node.js(npm)", PACKAGIST: "PHP(Composer)", PYPI: "Python(pip)",
                    RUBYGEMS: "Ruby(gem)", GO: "Go", CRATES: "Rust(crate)"}

SKIP_DIRS = {"node_modules", "vendor", ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", ".next",
             ".nuxt", "dist", "build", "out", ".cache", "site-packages", ".tox", ".mypy_cache", ".idea", ".vscode",
             "target"}
MAX_DEPTH = 6
_EXACT_RE = re.compile(r"^v?\d+(\.\d+)*([-+.]?[0-9A-Za-z.\-+]*)?$")


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str | None    # 確定した版。範囲指定しか無ければ None
    spec: str = ""         # 書かれていた指定("^14.0.0" 等)
    dev: bool = False      # 開発時だけ使う部品
    source: str = ""       # 読んだファイル(フォルダからの相対パス)


@dataclass
class Runtime:
    """Node.js・PHP 等の実行環境の版の指定。"""
    product: str        # endoflife.date の製品名(nodejs / php / python / go / ruby)
    cycle: str | None   # "20" "8.1" "3.11" 等。読み取れなければ None
    raw: str            # 書かれていた値
    source: str
    exact: bool         # True: この版で動かす指定 / False: 「これ以上」等の下限だけの指定


@dataclass
class WordPressSite:
    root: str
    version: str | None
    plugins: list = field(default_factory=list)  # [(slug, 表示名, 版 or None)]


@dataclass
class ScanResult:
    root: str
    packages: list = field(default_factory=list)
    files: list = field(default_factory=list)       # 読んだ一覧ファイル
    errors: list = field(default_factory=list)      # 読めなかったファイルと理由
    php_hints: list = field(default_factory=list)   # PHPを使っている手がかり
    php_requirement: str = ""                       # composer.json の require.php
    runtimes: list = field(default_factory=list)    # [Runtime]
    hostings: list = field(default_factory=list)    # [(置き場所の名前, 種類, 手がかりのファイル)]
    wordpress: list = field(default_factory=list)   # [WordPressSite]


# --- npm ---

def _npm_name_from_path(path):
    return path.rsplit("node_modules/", 1)[-1]


def parse_package_lock(text, source):
    data = json.loads(text)
    out = []
    if "packages" in data:  # lockfileVersion 2 / 3
        for path, info in data["packages"].items():
            if not path or info.get("link") or "version" not in info:
                continue
            out.append(Package(NPM, info.get("name") or _npm_name_from_path(path), info["version"],
                               dev=bool(info.get("dev") or info.get("devOptional")), source=source))
    else:  # lockfileVersion 1
        def walk(deps):
            for name, info in (deps or {}).items():
                if "version" in info and not str(info["version"]).startswith(("file:", "link:", "git")):
                    out.append(Package(NPM, name, info["version"], dev=bool(info.get("dev")), source=source))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def _yarn_spec_name(spec):
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)  # "@scope/name@^1" の先頭の @ は名前の一部
    return spec[:at] if at > 0 else spec


def parse_yarn_lock(text, source):
    out = []
    name = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            name = None if header.strip('"') == "__metadata" else _yarn_spec_name(header.split(",")[0])
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and name:
            if "@workspace:" not in line and not m.group(1).startswith("0.0.0-use.local"):
                out.append(Package(NPM, name, m.group(1), source=source))
            name = None
    return out


def parse_pnpm_lock(text, source):
    out = []
    in_packages = False
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            in_packages = line.startswith("packages:")
            current = None
            continue
        if not in_packages:
            continue
        m = re.match(r"^  '?/?(@?[^@\s'(]+)@([^:'(\s]+)[^:]*'?:\s*$", line)
        if m:
            current = Package(NPM, m.group(1), m.group(2), source=source)
            out.append(current)
        elif current and re.match(r"^\s+dev:\s*true", line):
            current.dev = True
    return out


def parse_package_json(text, source):
    data = json.loads(text)
    out = []
    for key, dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(key) or {}).items():
            spec = str(spec)
            exact = spec if _EXACT_RE.match(spec) and not spec.startswith(("^", "~")) else None
            out.append(Package(NPM, name, exact, spec, dev, source))
    return out


# --- Composer ---

def parse_composer_lock(text, source):
    data = json.loads(text)
    out = []
    for key, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(key) or []:
            version = str(p.get("version", ""))
            if version.startswith("dev-") or not version:
                version = None  # 開発中の枝を直接使っている(版が決まらない)
            out.append(Package(PACKAGIST, p["name"], version, str(p.get("version", "")), dev, source))
    return out


def parse_composer_json(text, source):
    data = json.loads(text)
    out = []
    for key, dev in (("require", False), ("require-dev", True)):
        for name, spec in (data.get(key) or {}).items():
            if "/" not in name:  # php・ext-xxx は部品ではない
                continue
            exact = spec.lstrip("v") if _EXACT_RE.match(spec) else None
            out.append(Package(PACKAGIST, name, exact, spec, dev, source))
    return out


# --- Python ---

def parse_requirements(text, source):
    out = []
    dev = bool(re.search(r"dev|test", os.path.basename(source), re.IGNORECASE))  # requirements-dev.txt 等
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        line = line.split(";", 1)[0].strip()  # 環境マーカー
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).strip()
        exact = spec[2:].strip() if spec.startswith("==") and "*" not in spec and "," not in spec else None
        out.append(Package(PYPI, name, exact, spec, dev, source))
    return out


def parse_poetry_lock(text, source):
    data = tomllib.loads(text)
    return [Package(PYPI, p["name"], p["version"], dev=p.get("category") == "dev", source=source)
            for p in data.get("package", []) if "version" in p]


def parse_uv_lock(text, source):
    data = tomllib.loads(text)
    out = []
    for p in data.get("package", []):
        src = p.get("source", {})
        if "version" not in p or "editable" in src or "virtual" in src:
            continue  # 自分のプロジェクト自身
        out.append(Package(PYPI, p["name"], p["version"], source=source))
    return out


def parse_pipfile_lock(text, source):
    data = json.loads(text)
    out = []
    for key, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(key) or {}).items():
            version = str(info.get("version", ""))
            out.append(Package(PYPI, name, version[2:] if version.startswith("==") else None, version, dev, source))
    return out


# --- Ruby / Go / Rust ---

_GEM_PLATFORM_RE = re.compile(r"-(x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux)[\w.-]*$")


def parse_gemfile_lock(text, source):
    out = []
    section = None
    in_specs = False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if section == "GEM" and in_specs and m:  # GIT・PATH の部品は版が決まらないので読まない
            out.append(Package(RUBYGEMS, m.group(1), _GEM_PLATFORM_RE.sub("", m.group(2)), source=source))
    return out


def parse_go_mod(text, source):
    out = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)$", line)
        if m and (in_block or line.startswith("require ")):
            out.append(Package(GO, m.group(1), m.group(2), source=source))
    return out


def parse_cargo_lock(text, source):
    data = tomllib.loads(text)
    return [Package(CRATES, p["name"], p["version"], source=source)
            for p in data.get("package", []) if str(p.get("source", "")).startswith("registry+")]


# --- 実行環境の版 ---

_RUNTIME_IMAGES = {"node": "nodejs", "php": "php", "python": "python", "golang": "go", "ruby": "ruby"}
_ASDF_NAMES = {"nodejs": "nodejs", "node": "nodejs", "php": "php", "python": "python", "golang": "go",
               "go": "go", "ruby": "ruby"}


def runtime_cycle(product, text):
    """"v20.11.0" → "20"(nodejs)、"3.11.4" → "3.11"。読めなければ None。"""
    m = re.search(r"(\d+)(?:\.(\d+))?", text or "")
    if not m:
        return None
    if product == "nodejs":
        return m.group(1)
    return f"{m.group(1)}.{m.group(2)}" if m.group(2) else None


def read_runtimes(dirpath, names, rel):
    out = []

    def read(fname):
        with open(os.path.join(dirpath, fname), encoding="utf-8-sig", errors="replace") as f:
            return f.read()

    def add(product, raw, label, exact):
        out.append(Runtime(product, runtime_cycle(product, raw), raw.strip()[:60],
                           os.path.normpath(os.path.join(rel, label)), exact))

    for fname, product in ((".nvmrc", "nodejs"), (".node-version", "nodejs"), (".python-version", "python"),
                           (".ruby-version", "ruby")):
        if fname in names:
            lines = read(fname).strip().splitlines()
            if lines and re.search(r"\d", lines[0]):
                add(product, lines[0], fname, True)
    if "runtime.txt" in names:
        m = re.search(r"python-(\d[\d.]*)", read("runtime.txt"))
        if m:
            add("python", m.group(1), "runtime.txt", True)
    if ".tool-versions" in names:
        for line in read(".tool-versions").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in _ASDF_NAMES:
                add(_ASDF_NAMES[parts[0]], parts[1], ".tool-versions", True)
    for fname, product, getter in (
            ("package.json", "nodejs", lambda t: (json.loads(t).get("engines") or {}).get("node")),
            ("composer.json", "php", lambda t: (json.loads(t).get("require") or {}).get("php")),
            ("pyproject.toml", "python", lambda t: (tomllib.loads(t).get("project") or {}).get("requires-python"))):
        if fname in names:
            try:
                value = getter(read(fname))
            except (ValueError, AttributeError, tomllib.TOMLDecodeError):
                value = None
            if value:
                add(product, str(value), f"{fname}(下限の指定)", False)
    if "go.mod" in names:
        m = re.search(r"^go\s+(\d+\.\d+)", read("go.mod"), re.MULTILINE)
        if m:
            add("go", m.group(1), "go.mod(下限の指定)", False)
    for fname in sorted(n for n in names if n == "Dockerfile" or n.startswith("Dockerfile.")
                        or n.endswith(".Dockerfile")):
        for m in re.finditer(r"^\s*FROM\s+(?:--\S+\s+)*(?:docker\.io/)?(?:library/)?([a-z]+):([\w.\-]+)",
                             read(fname), re.MULTILINE | re.IGNORECASE):
            image, tag = m.group(1).lower(), m.group(2)
            if image in _RUNTIME_IMAGES and re.match(r"\d", tag):
                add(_RUNTIME_IMAGES[image], tag, f"{fname}(FROM {image}:{tag})", True)
    return out


# --- 置き場所の手がかり ---

HOSTING_FILES = [
    ("vercel.json", "Vercel", "paas"), ("netlify.toml", "Netlify", "static"), ("fly.toml", "Fly.io", "paas"),
    ("render.yaml", "Render", "paas"), ("Procfile", "Heroku 等", "paas"), ("app.yaml", "Google App Engine", "paas"),
    ("firebase.json", "Firebase", "static"), ("wrangler.toml", "Cloudflare", "paas"),
    ("wrangler.jsonc", "Cloudflare", "paas"), ("amplify.yml", "AWS Amplify", "paas"),
    ("docker-compose.yml", "Docker(自分のサーバーの可能性)", "self"),
    ("compose.yaml", "Docker(自分のサーバーの可能性)", "self"),
]


def read_hostings(root):
    """置き場所の手がかりになる設定ファイルを探す(フォルダの一番上と、その1つ下まで)。"""
    out = []
    try:
        subdirs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))
                         and d not in SKIP_DIRS and not d.startswith("."))
    except OSError:
        return out
    for d in [root] + [os.path.join(root, s) for s in subdirs]:
        try:
            names = set(os.listdir(d))
        except OSError:
            continue
        rel = os.path.relpath(d, root)
        for fname, name, kind in HOSTING_FILES:
            if fname in names:
                out.append((name, kind, os.path.normpath(os.path.join(rel, fname))))
        if ".vercel" in names:
            out.append(("Vercel", "paas", os.path.normpath(os.path.join(rel, ".vercel"))))
        workflows = os.path.join(d, ".github", "workflows")
        if os.path.isdir(workflows):
            for wf in sorted(os.listdir(workflows)):
                try:
                    with open(os.path.join(workflows, wf), encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except OSError:
                    continue
                if re.search(r"\b(ssh|scp|rsync)\b", text):
                    out.append(("自分のサーバー(GitHub Actions から転送)", "self",
                                os.path.normpath(os.path.join(rel, ".github", "workflows", wf))))
    seen, unique = set(), []
    for h in out:
        if h[0] not in seen:
            seen.add(h[0])
            unique.append(h)
    return unique


# --- WordPress ---

def read_wordpress(dirpath, rel):
    """wp-includes/version.php から WordPress 本体の版を、プラグインの先頭の説明から版を読む。"""
    version = None
    try:
        with open(os.path.join(dirpath, "wp-includes", "version.php"), encoding="utf-8", errors="replace") as f:
            m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", f.read())
            version = m.group(1) if m else None
    except OSError:
        pass
    site = WordPressSite(rel, version)
    plugins_dir = os.path.join(dirpath, "wp-content", "plugins")
    if not os.path.isdir(plugins_dir):
        return site
    for entry in sorted(os.listdir(plugins_dir)):
        path = os.path.join(plugins_dir, entry)
        if os.path.isdir(path):
            files = [os.path.join(path, f) for f in sorted(os.listdir(path)) if f.lower().endswith(".php")]
            slug = entry
        elif entry.lower().endswith(".php") and entry != "index.php":
            files, slug = [path], entry[:-4]
        else:
            continue
        for php in files:  # プラグインの一番上の .php の先頭にある「Plugin Name:」「Version:」だけを読む
            try:
                with open(php, encoding="utf-8", errors="replace") as f:
                    head = f.read(8192)
            except OSError:
                continue
            name = re.search(r"^[ \t/*#@]*Plugin Name:\s*(.+)$", head, re.MULTILINE | re.IGNORECASE)
            if name:
                ver = re.search(r"^[ \t/*#@]*Version:\s*([^\s*]+)", head, re.MULTILINE | re.IGNORECASE)
                site.plugins.append((slug, name.group(1).strip()[:80], ver.group(1) if ver else None))
                break
    return site


# --- フォルダを歩く ---

# 同じフォルダに複数あれば、先に書いたものだけを使う(lock があれば範囲指定のファイルは読まない)
GROUPS = [
    [("package-lock.json", parse_package_lock), ("npm-shrinkwrap.json", parse_package_lock),
     ("yarn.lock", parse_yarn_lock), ("pnpm-lock.yaml", parse_pnpm_lock), ("package.json", parse_package_json)],
    [("composer.lock", parse_composer_lock), ("composer.json", parse_composer_json)],
    [("poetry.lock", parse_poetry_lock), ("uv.lock", parse_uv_lock), ("Pipfile.lock", parse_pipfile_lock),
     ("requirements*.txt", parse_requirements)],
    [("Gemfile.lock", parse_gemfile_lock)],
    [("go.mod", parse_go_mod)],
    [("Cargo.lock", parse_cargo_lock)],
]


def _match(filenames, pattern):
    if "*" in pattern:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$", re.IGNORECASE)
        return sorted(f for f in filenames if rx.match(f))
    return [pattern] if pattern in filenames else []


def scan_folder(root):
    result = ScanResult(root)
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.relpath(dirpath, root).count(os.sep) + (dirpath != root)
        dirnames[:] = [] if depth >= MAX_DEPTH else sorted(
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        names = set(filenames)
        rel_dir = os.path.relpath(dirpath, root)
        if any(f.lower().endswith(".php") for f in filenames):
            result.php_hints.append(rel_dir + "\\*.php")
        if os.path.isfile(os.path.join(dirpath, "wp-includes", "version.php")):
            result.wordpress.append(read_wordpress(dirpath, rel_dir))
            # WordPress 本体・プラグインの中には入らない(同梱物で数が膨大。プラグインは read_wordpress で読んだ)
            dirnames[:] = [d for d in dirnames if d not in ("wp-includes", "wp-admin", "wp-content")]
        try:
            result.runtimes += read_runtimes(dirpath, names, rel_dir)
        except OSError as e:
            result.errors.append(f"{rel_dir}: {type(e).__name__}")
        for group in GROUPS:
            for pattern, parser in group:
                matched = _match(names, pattern)
                if not matched:
                    continue
                for fname in matched:
                    path = os.path.join(dirpath, fname)
                    rel = os.path.relpath(path, root)
                    try:
                        with open(path, encoding="utf-8-sig") as f:
                            text = f.read()
                        result.packages += parser(text, rel)
                        result.files.append(rel)
                    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as e:
                        result.errors.append(f"{rel}: {type(e).__name__}")
                break
        if "composer.json" in names or "composer.lock" in names:
            result.php_hints.append(os.path.relpath(os.path.join(dirpath, "composer.json"), root))
        if "composer.json" in names:  # composer.lock があっても、PHP本体の指定は composer.json にしか無い
            try:
                with open(os.path.join(dirpath, "composer.json"), encoding="utf-8-sig") as f:
                    req = (json.load(f).get("require") or {}).get("php")
                if req:
                    result.php_requirement = str(req)
            except (OSError, ValueError, AttributeError):
                pass
    result.packages = _dedupe(result.packages)
    result.hostings = read_hostings(root)
    return result


def _dedupe(packages):
    """同じ部品・同じ版は1つにまとめる。どこかで本番用に使われていれば本番用扱い。"""
    merged = {}
    for p in packages:
        key = (p.ecosystem, p.name.lower(), p.version or "", p.spec if p.version is None else "")
        if key in merged:
            merged[key].dev = merged[key].dev and p.dev
        else:
            merged[key] = p
    return list(merged.values())
