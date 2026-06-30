#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
LOCAL_BIN = TOOLS_HOME / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
NPM_HOME = TOOLS_HOME / "npm"
NPM_BIN = NPM_HOME / "bin"
SRC_HOME = TOOLS_HOME / "src"
VENV_BIN = Path(sys.executable).resolve().parent
LOG_DIR = Path("reports/output/top100-tools/install-logs")

ALIASES: dict[str, list[str]] = {
    "python": ["python", "python3"],
    "pip": ["pip", "pip3"],
    "node": ["node", "nodejs"],
    "testssl.sh": ["testssl.sh", "testssl"],
    "retire-js": ["retire-js", "retire"],
    "npm-audit": ["npm-audit", "npm"],
    "SecretFinder": ["SecretFinder", "SecretFinder.py", "secretfinder"],
    "LinkFinder": ["LinkFinder", "LinkFinder.py", "linkfinder", "linkfinder.py"],
    "cyclonedx-py": ["cyclonedx-py", "cyclonedx-bom"],
    "getJS": ["getJS", "getjs"],
    "zap-baseline.py": ["zap-baseline.py", "zap-baseline"],
    "chromedriver": ["chromedriver", "chromium-driver"],
    "firefox": ["firefox", "firefox-esr"],
    "wappalyzer": ["wappalyzer"],
    "osv-scanner": ["osv-scanner", "osv"],
}

RECIPES: dict[str, dict[str, Any]] = {
    "gitleaks": {"method": "release", "repo": "gitleaks/gitleaks", "asset_terms": [["linux", "x64"], ["linux", "amd64"], ["linux", "64"]], "fallback": {"method": "go", "package": "github.com/gitleaks/gitleaks/v8@latest"}},
    "trufflehog": {"method": "release", "repo": "trufflesecurity/trufflehog", "asset_terms": [["linux", "amd64"], ["linux", "x86_64"], ["linux", "64bit"]], "fallback": {"method": "go", "package": "github.com/trufflesecurity/trufflehog/v3@latest"}},
    "mantra": {"method": "go", "package": "github.com/MrEmpy/mantra@latest"},
    "jsluice": {"method": "release", "repo": "BishopFox/jsluice", "asset_terms": [["linux", "amd64"], ["linux", "x86_64"], ["linux", "64bit"]], "fallback": {"method": "go", "package": "github.com/BishopFox/jsluice/cmd/jsluice@latest"}},
    "getJS": {"method": "go", "package": "github.com/003random/getJS/v2@latest", "fallback_wrapper": "getjs"},
    "osv-scanner": {"method": "release", "repo": "google/osv-scanner", "asset_terms": [["linux", "amd64"], ["linux", "x86_64"], ["linux", "64bit"]], "fallback": {"method": "go", "package": "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}},
    "curlie": {"method": "go", "package": "github.com/rs/curlie@latest"},
    "trivy": {"method": "release", "repo": "aquasecurity/trivy", "asset_terms": [["linux", "64bit"], ["linux", "amd64"], ["linux", "x86_64"]], "fallback": {"method": "go", "package": "github.com/aquasecurity/trivy/cmd/trivy@latest"}},
    "grype": {"method": "release", "repo": "anchore/grype", "asset_terms": [["linux", "amd64"], ["linux", "x86_64"], ["linux", "64bit"]], "fallback": {"method": "go", "package": "github.com/anchore/grype/cmd/grype@latest"}},
    "syft": {"method": "release", "repo": "anchore/syft", "asset_terms": [["linux", "amd64"], ["linux", "x86_64"], ["linux", "64bit"]], "fallback": {"method": "go", "package": "github.com/anchore/syft/cmd/syft@latest"}},
    "semgrep": {"method": "pip", "package": "semgrep"},
    "safety": {"method": "pip", "package": "safety"},
    "pip-audit": {"method": "pip", "package": "pip-audit"},
    "sublist3r": {"method": "pip", "package": "git+https://github.com/aboul3la/Sublist3r.git"},
    "SecretFinder": {"method": "git_wrapper", "repo": "https://github.com/m4ll0k/SecretFinder.git", "script": "SecretFinder.py"},
    "detect-secrets": {"method": "pip", "package": "detect-secrets"},
    "checkov": {"method": "pip", "package": "checkov"},
    "cyclonedx-py": {"method": "pip", "package": "cyclonedx-bom"},
    "httpie": {"method": "pip", "package": "httpie"},
    "crtsh": {"method": "python_wrapper", "kind": "crtsh"},
    "wappalyzer": {"method": "npm_wrapper", "package": "wappalyzer", "wrapper": "wappalyzer"},
    "retire": {"method": "npm", "package": "retire"},
    "retire-js": {"method": "npm_alias", "alias_to": "retire"},
    "yarn": {"method": "npm", "package": "yarn"},
    "pnpm": {"method": "npm", "package": "pnpm"},
    "snyk": {"method": "npm", "package": "snyk"},
    "npm-audit": {"method": "python_wrapper", "kind": "npm-audit"},
    "xh": {"method": "cargo", "package": "xh"},
    "cargo-audit": {"method": "cargo", "package": "cargo-audit"},
    "bundler-audit": {"method": "gem", "package": "bundler-audit"},
    "cargo": {"method": "apt", "package": "cargo"},
    "massdns": {"method": "apt", "package": "massdns"},
    "lynis": {"method": "apt", "package": "lynis"},
    "zap-baseline.py": {"method": "apt", "package": "zaproxy", "post": "zap-wrapper"},
    "testssl.sh": {"method": "git_script", "repo": "https://github.com/drwetter/testssl.sh.git", "script": "testssl.sh"},
}


def ensure_dirs() -> None:
    for path in [TOOLS_HOME, LOCAL_BIN, GO_BIN, USER_LOCAL_BIN, NPM_HOME, NPM_BIN, SRC_HOME, LOG_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def install_env() -> dict[str, str]:
    ensure_dirs()
    env = dict(os.environ)
    extra = [str(LOCAL_BIN), str(NPM_BIN), str(GO_BIN), str(USER_LOCAL_BIN), str(VENV_BIN)]
    gem_root = Path.home() / ".gem"
    if gem_root.exists():
        extra += [str(p) for p in gem_root.glob("ruby/*/bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env["GOBIN"] = str(LOCAL_BIN)
    env["GOPATH"] = str(Path.home() / "go")
    env["npm_config_prefix"] = str(NPM_HOME)
    return env


def names_for(name: str, binary: str | None = None) -> list[str]:
    values = [binary or name, name]
    for key in [name, binary or "", str(name).lower(), str(binary or "").lower()]:
        values.extend(ALIASES.get(key, []))
    return list(dict.fromkeys([x for x in values if x]))


def chmod_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def find_binary(name: str, binary: str | None = None) -> str | None:
    env = install_env()
    for candidate in names_for(name, binary):
        found = shutil.which(candidate, path=env.get("PATH"))
        if found:
            return found
    wanted = {x.lower() for x in names_for(name, binary)}
    for root in [LOCAL_BIN, NPM_BIN, GO_BIN, USER_LOCAL_BIN, VENV_BIN, TOOLS_HOME, Path.home() / ".gem"]:
        if not root.exists():
            continue
        try:
            for item in root.rglob("*"):
                if item.is_file() and item.name.lower() in wanted:
                    chmod_exec(item)
                    return str(item)
        except Exception:
            pass
    return None


def has_recipe(name: str, binary: str | None = None) -> bool:
    return name in RECIPES or (binary or "") in RECIPES


def recipe_for(name: str, binary: str | None = None) -> dict[str, Any] | None:
    return RECIPES.get(name) or RECIPES.get(binary or "")


def method_for(name: str, binary: str | None = None) -> str:
    recipe = recipe_for(name, binary)
    return str(recipe.get("method")) if recipe else "manual"


def run_command(command: list[str], log_path: Path, *, timeout: int = 1200) -> tuple[bool, int]:
    ensure_dirs()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        log.flush()
        try:
            proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=install_env(), timeout=timeout)
            return proc.returncode == 0, int(proc.returncode)
        except subprocess.TimeoutExpired:
            log.write(f"\nTIMEOUT after {timeout}s\n")
            return False, 124
        except Exception as exc:
            log.write(f"\nEXCEPTION: {exc}\n")
            return False, 1


def append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="ignore") as log:
        log.write(text.rstrip() + "\n")


def symlink_or_copy(found: str, name: str, binary: str | None = None) -> None:
    ensure_dirs()
    src = Path(found)
    chmod_exec(src)
    target = LOCAL_BIN / names_for(name, binary)[0]
    try:
        if target.exists() or target.is_symlink():
            try:
                if target.resolve() == src.resolve():
                    chmod_exec(target)
                    return
            except Exception:
                pass
            target.unlink()
        target.symlink_to(src)
    except Exception:
        try:
            shutil.copy2(src, target)
        except Exception:
            return
    chmod_exec(target)


def create_python_wrapper(name: str, lines: list[str]) -> Path:
    ensure_dirs()
    path = LOCAL_BIN / name
    path.write_text("\n".join(["#!/usr/bin/env python3", *lines, ""]), encoding="utf-8")
    chmod_exec(path)
    return path


def create_builtin_wrapper(kind: str, name: str, binary: str) -> bool:
    if kind == "npm-audit":
        if not find_binary("npm", "npm"):
            return False
        create_python_wrapper("npm-audit", ["import subprocess, sys", "raise SystemExit(subprocess.call(['npm', 'audit'] + sys.argv[1:]))"])
        return True
    if kind == "crtsh":
        create_python_wrapper("crtsh", [
            "import json, sys, urllib.parse, urllib.request",
            "q = sys.argv[1] if len(sys.argv) > 1 else ''",
            "if not q:",
            "    print('usage: crtsh <domain>')",
            "    raise SystemExit(2)",
            "url = 'https://crt.sh/?q=' + urllib.parse.quote(q) + '&output=json'",
            "try:",
            "    data = urllib.request.urlopen(url, timeout=25).read().decode('utf-8', 'ignore')",
            "    rows = json.loads(data)",
            "except Exception as exc:",
            "    print(f'crtsh error: {exc}', file=sys.stderr)",
            "    raise SystemExit(1)",
            "seen = set()",
            "for row in rows:",
            "    for item in str(row.get('name_value', '')).replace('\\\\n', chr(10)).splitlines():",
            "        item = item.strip().lstrip('*.')",
            "        if item and item not in seen:",
            "            seen.add(item)",
            "            print(item)",
        ])
        return True
    if kind == "getjs":
        create_python_wrapper("getJS", [
            "import re, sys, urllib.parse, urllib.request",
            "url = sys.argv[1] if len(sys.argv) > 1 else ''",
            "if not url:",
            "    print('usage: getJS <url>')",
            "    raise SystemExit(2)",
            "try:",
            "    html = urllib.request.urlopen(url, timeout=20).read().decode('utf-8', 'ignore')",
            "except Exception as exc:",
            "    print(f'getJS error: {exc}', file=sys.stderr)",
            "    raise SystemExit(1)",
            "pattern = r'<script[^>]+src=[\"\\\\\']([^\"\\\\\']+)'",
            "for src in sorted(set(re.findall(pattern, html, re.I))):",
            "    print(urllib.parse.urljoin(url, src))",
        ])
        return True
    return False


def install_apt(package: str, log_path: Path) -> tuple[bool, str]:
    if os.geteuid() == 0:
        ok, code = run_command(["apt-get", "install", "-y", package], log_path, timeout=1800)
        return ok, f"apt_exit={code}"
    sudo = shutil.which("sudo")
    if not sudo:
        return False, "sudo_missing"
    subprocess.call([sudo, "-v"])
    run_command([sudo, "-n", "apt-get", "update"], log_path, timeout=1800)
    ok, code = run_command([sudo, "-n", "apt-get", "install", "-y", package], log_path, timeout=1800)
    return ok, f"apt_exit={code}"


def install_go_package(package: str, log_path: Path) -> tuple[bool, str]:
    go = find_binary("go", "go") or shutil.which("go")
    details = ""
    if not go:
        bootstrap_ok, bootstrap_detail = install_apt("golang-go", log_path)
        details += f"bootstrap_go={bootstrap_ok} {bootstrap_detail}; "
        go = find_binary("go", "go") or shutil.which("go")
    if not go:
        return False, details + "go_missing"
    ok, code = run_command([go, "install", package], log_path, timeout=2400)
    return ok, details + f"go_exit={code}"


def latest_release_json(repo: str, log_path: Path) -> dict[str, Any] | None:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScope-Installer/1.0", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as exc:
        append_log(log_path, f"release_api_error repo={repo}: {exc}")
        return None


def asset_score(asset_name: str, terms_sets: list[list[str]]) -> int:
    low = asset_name.lower()
    blocked = ["sha256", "checksum", "checksums", ".sig", ".pem", ".asc", ".sbom", ".spdx", ".rpm", ".deb", ".apk"]
    if any(x in low for x in blocked):
        return -999
    archive_bonus = 0
    if low.endswith((".tar.gz", ".tgz", ".zip")):
        archive_bonus = 20
    elif low.endswith(".gz"):
        archive_bonus = 8
    elif "linux" in low:
        archive_bonus = 5
    best = -999
    for terms in terms_sets:
        if all(term.lower() in low for term in terms):
            score = archive_bonus + len(terms) * 10
            if any(x in low for x in ["amd64", "x86_64", "x64", "64bit"]):
                score += 5
            best = max(best, score)
    return best


def download_file(url: str, dest: Path, log_path: Path) -> bool:
    append_log(log_path, f"download {url} -> {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScope-Installer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp, dest.open("wb") as fh:
            shutil.copyfileobj(resp, fh)
        return dest.exists() and dest.stat().st_size > 0
    except Exception as exc:
        append_log(log_path, f"download_error: {exc}")
        return False


def safe_extract_tar(archive: Path, dest: Path) -> None:
    with tarfile.open(archive, "r:*") as tf:
        base = dest.resolve()
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(base)):
                raise RuntimeError(f"blocked unsafe archive path: {member.name}")
        tf.extractall(dest)


def extract_archive(archive: Path, dest: Path, log_path: Path) -> bool:
    try:
        name = archive.name.lower()
        if name.endswith((".tar.gz", ".tgz", ".tar")):
            safe_extract_tar(archive, dest)
            return True
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(dest)
            return True
        if name.endswith(".gz"):
            out = dest / archive.name[:-3]
            with gzip.open(archive, "rb") as src, out.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            chmod_exec(out)
            return True
        out = dest / archive.name
        shutil.copy2(archive, out)
        chmod_exec(out)
        return True
    except Exception as exc:
        append_log(log_path, f"extract_error: {exc}")
        return False


def locate_extracted_binary(dest: Path, name: str, binary: str | None = None) -> str | None:
    wanted = {x.lower() for x in names_for(name, binary)}
    fallback: list[Path] = []
    for item in dest.rglob("*"):
        if not item.is_file():
            continue
        if item.name.lower() in wanted:
            chmod_exec(item)
            return str(item)
        if item.stat().st_size > 0:
            mode = item.stat().st_mode
            if mode & stat.S_IXUSR and not item.name.lower().endswith((".md", ".txt", ".json", ".yaml", ".yml")):
                fallback.append(item)
    if len(fallback) == 1:
        chmod_exec(fallback[0])
        return str(fallback[0])
    return None


def install_release(name: str, binary: str, recipe: dict[str, Any], log_path: Path) -> tuple[bool, str]:
    repo = str(recipe.get("repo") or "")
    if not repo:
        return False, "release_repo_missing"
    release = latest_release_json(repo, log_path)
    if not release:
        return False, "release_lookup_failed"
    assets = release.get("assets", [])
    terms_sets = recipe.get("asset_terms") or [["linux", "amd64"], ["linux", "x86_64"], ["linux", "x64"], ["linux", "64bit"]]
    scored: list[tuple[int, dict[str, Any]]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        asset_name = str(asset.get("name") or "")
        score = asset_score(asset_name, terms_sets)
        if score > 0:
            scored.append((score, asset))
    scored.sort(key=lambda x: x[0], reverse=True)
    if not scored:
        append_log(log_path, "release_assets_seen=" + ", ".join(str(a.get("name")) for a in assets if isinstance(a, dict))[:2000])
        return False, "release_asset_not_found"
    asset = scored[0][1]
    asset_name = str(asset.get("name"))
    url = str(asset.get("browser_download_url") or "")
    if not url:
        return False, "release_asset_url_missing"
    with tempfile.TemporaryDirectory(prefix=f"vulnscope-{name}-") as td:
        tmp = Path(td)
        archive = tmp / asset_name
        if not download_file(url, archive, log_path):
            return False, "release_download_failed"
        extract_dir = tmp / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        if not extract_archive(archive, extract_dir, log_path):
            return False, "release_extract_failed"
        found = locate_extracted_binary(extract_dir, name, binary)
        if not found:
            append_log(log_path, f"release_binary_not_found asset={asset_name}")
            return False, "release_binary_not_found"
        symlink_or_copy(found, name, binary)
    final = find_binary(name, binary)
    return final is not None, f"release_asset={asset_name}"


def install_npm_package(package: str, log_path: Path) -> tuple[bool, str]:
    npm = find_binary("npm", "npm") or shutil.which("npm")
    if not npm:
        install_apt("npm", log_path)
        npm = find_binary("npm", "npm") or shutil.which("npm")
    if not npm:
        return False, "npm_missing"
    ok, code = run_command([npm, "install", "-g", "--prefix", str(NPM_HOME), package], log_path, timeout=1800)
    return ok, f"npm_exit={code}"


def create_npx_wrapper(command_name: str, package: str) -> None:
    create_python_wrapper(command_name, [
        "import shutil, subprocess, sys",
        "npx = shutil.which('npx') or shutil.which('npx.cmd')",
        "if not npx:",
        "    print('npx not found; install npm/node first', file=sys.stderr)",
        "    raise SystemExit(127)",
        f"raise SystemExit(subprocess.call([npx, '--yes', {package!r}] + sys.argv[1:]))",
    ])


def install_one(name: str, binary: str | None = None, *, yes: bool = True) -> dict[str, Any]:
    ensure_dirs()
    started = time.time()
    binary = binary or name
    before = find_binary(name, binary)
    if before:
        return {"tool": name, "binary": binary, "ok": True, "status": "already_installed", "path": before, "seconds": 0.0}
    recipe = recipe_for(name, binary)
    if not recipe:
        return {"tool": name, "binary": binary, "ok": False, "status": "no_recipe", "seconds": 0.0}
    method = str(recipe.get("method"))
    package = str(recipe.get("package") or "")
    log_path = LOG_DIR / f"{re.sub(r'[^a-zA-Z0-9_.-]+', '-', name).lower()}.log"
    ok = False
    details = ""
    try:
        if method == "release":
            ok, details = install_release(name, binary, recipe, log_path)
            if not ok and isinstance(recipe.get("fallback"), dict):
                fallback = dict(recipe["fallback"])
                if str(fallback.get("method")) == "go":
                    fb_ok, fb_details = install_go_package(str(fallback.get("package") or ""), log_path)
                    ok = fb_ok or ok
                    details += f"; fallback_go={fb_details}"
        elif method == "go":
            ok, details = install_go_package(package, log_path)
        elif method == "pip":
            ok, code = run_command([sys.executable, "-m", "pip", "install", "--upgrade", package], log_path, timeout=1800)
            details = f"pip_exit={code}"
        elif method == "npm":
            ok, details = install_npm_package(package, log_path)
        elif method == "npm_wrapper":
            install_npm_package(package, log_path)
            create_npx_wrapper(str(recipe.get("wrapper") or binary), package)
            ok = True
            details = f"npm_wrapper={package}"
        elif method == "npm_alias":
            alias_to = str(recipe.get("alias_to") or package)
            install_one(alias_to, alias_to, yes=yes)
            found_alias = find_binary(alias_to, alias_to)
            if found_alias:
                create_python_wrapper(name, ["import subprocess, sys", f"raise SystemExit(subprocess.call([{found_alias!r}] + sys.argv[1:]))"])
                ok = True
            details = f"alias_to={alias_to}"
        elif method == "cargo":
            cargo = find_binary("cargo", "cargo") or shutil.which("cargo")
            if not cargo:
                install_apt("cargo", log_path)
                cargo = find_binary("cargo", "cargo") or shutil.which("cargo")
            if cargo:
                ok, code = run_command([cargo, "install", package], log_path, timeout=2400)
                details = f"cargo_exit={code}"
            else:
                details = "cargo_missing"
        elif method == "gem":
            gem = find_binary("gem", "gem") or shutil.which("gem")
            if not gem:
                install_apt("ruby", log_path)
                gem = find_binary("gem", "gem") or shutil.which("gem")
            if gem:
                ok, code = run_command([gem, "install", "--user-install", package], log_path, timeout=1800)
                details = f"gem_exit={code}"
            else:
                details = "gem_missing"
        elif method == "apt":
            ok, details = install_apt(package, log_path)
        elif method == "git_script":
            repo = str(recipe.get("repo") or "")
            script = str(recipe.get("script") or binary)
            dest = SRC_HOME / name.replace("/", "-")
            if dest.exists() and (dest / ".git").exists():
                run_command(["git", "-C", str(dest), "pull", "--ff-only"], log_path, timeout=900)
            else:
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                run_command(["git", "clone", "--depth", "1", repo, str(dest)], log_path, timeout=1800)
            script_path = dest / script
            if script_path.exists():
                symlink_or_copy(str(script_path), name, binary)
                ok = True
            details = f"git_script={script}"
        elif method == "git_wrapper":
            repo = str(recipe.get("repo") or "")
            script = str(recipe.get("script") or binary)
            dest = SRC_HOME / name.replace("/", "-")
            if dest.exists() and (dest / ".git").exists():
                run_command(["git", "-C", str(dest), "pull", "--ff-only"], log_path, timeout=900)
            else:
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                run_command(["git", "clone", "--depth", "1", repo, str(dest)], log_path, timeout=1800)
            script_path = dest / script
            if script_path.exists():
                create_python_wrapper(binary, ["import subprocess, sys", f"raise SystemExit(subprocess.call([{sys.executable!r}, {str(script_path)!r}] + sys.argv[1:]))"])
                ok = True
            details = f"git_wrapper={script}"
        elif method == "python_wrapper":
            ok = bool(create_builtin_wrapper(str(recipe.get("kind")), name, binary))
            details = f"python_wrapper={recipe.get('kind')}"
        else:
            details = f"unsupported_method={method}"

        if str(recipe.get("post") or "") == "zap-wrapper":
            for candidate in [Path("/usr/share/zaproxy/zap-baseline.py"), Path("/usr/bin/zap-baseline.py")]:
                if candidate.exists():
                    create_python_wrapper("zap-baseline.py", ["import subprocess, sys", f"raise SystemExit(subprocess.call(['python3', {str(candidate)!r}] + sys.argv[1:]))"])
                    break

        found = find_binary(name, binary)
        if found:
            symlink_or_copy(found, name, binary)
        if not found and method == "go":
            for root in [LOCAL_BIN, GO_BIN, Path.home() / "go" / "bin"]:
                if not root.exists():
                    continue
                for item in root.rglob("*"):
                    if item.is_file() and item.name.lower() in {x.lower() for x in names_for(name, binary)}:
                        symlink_or_copy(str(item), name, binary)
                        found = str(LOCAL_BIN / names_for(name, binary)[0])
                        break
                if found:
                    break
        fallback = recipe.get("fallback_wrapper")
        if not found and fallback and create_builtin_wrapper(str(fallback), name, binary):
            found = find_binary(name, binary)
        if not found and method == "npm_wrapper":
            found = find_binary(name, binary)
        status = "installed_or_repaired" if found else "install_attempted_binary_not_found" if ok else "install_failed"
        return {"tool": name, "binary": binary, "method": method, "package": package, "ok": bool(found), "status": status, "path": found, "details": details, "log": str(log_path), "seconds": round(time.time() - started, 2)}
    except Exception as exc:
        append_log(log_path, f"installer_exception: {exc}")
        return {"tool": name, "binary": binary, "method": method, "package": package, "ok": False, "status": "install_exception", "path": None, "details": str(exc)[:500], "log": str(log_path), "seconds": round(time.time() - started, 2)}


def install_missing_from_inventory(rows: list[dict[str, Any]], *, max_install: int = 100, yes: bool = True) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    started = time.time()
    missing = [r for r in rows if not r.get("installed") and has_recipe(str(r.get("name")), str(r.get("binary") or r.get("name")))]
    for index, row in enumerate(missing[:max_install], 1):
        name = str(row.get("name"))
        binary = str(row.get("binary") or name)
        print(f"[{index:03d}/{len(missing):03d}] Installing/checking {name} via {method_for(name, binary)} ...", flush=True)
        result = install_one(name, binary, yes=yes)
        print(f"      status={result.get('status')} ok={result.get('ok')} path={result.get('path') or '-'} seconds={result.get('seconds')}", flush=True)
        results.append(result)
    return {"generated_at": time.time(), "summary": {"attempted": len(results), "installed_or_repaired": len([r for r in results if r.get("ok")]), "failed": len([r for r in results if not r.get("ok")]), "seconds": round(time.time() - started, 2)}, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(description="Universal VulnScope Top100 tool installer")
    parser.add_argument("tool", nargs="?")
    parser.add_argument("--binary")
    parser.add_argument("--list-recipes", action="store_true")
    args = parser.parse_args()
    if args.list_recipes:
        print(json.dumps({"recipes": sorted(RECIPES), "count": len(RECIPES)}, indent=2))
        return 0
    if not args.tool:
        print(json.dumps({"error": "tool name required unless --list-recipes is used"}, indent=2))
        return 2
    print(json.dumps(install_one(args.tool, args.binary or args.tool), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
