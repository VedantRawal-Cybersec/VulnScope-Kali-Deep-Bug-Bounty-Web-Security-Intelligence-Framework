#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from safe_tool_adapter import create_safe_adapter, is_adapter, names_for as adapter_names_for

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
LOCAL_BIN = TOOLS_HOME / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
NPM_HOME = TOOLS_HOME / "npm"
NPM_BIN = NPM_HOME / "bin"
SRC_HOME = TOOLS_HOME / "src"
VENV_BIN = Path(sys.executable).resolve().parent
LOG_DIR = Path("reports/output/top100-tools/install-logs")

RECIPES: dict[str, dict[str, Any]] = {
    "gitleaks": {"method": "go", "package": "github.com/gitleaks/gitleaks/v8@latest"},
    "trufflehog": {"method": "go", "package": "github.com/trufflesecurity/trufflehog/v3@latest"},
    "mantra": {"method": "go", "package": "github.com/MrEmpy/mantra@latest"},
    "jsluice": {"method": "go", "package": "github.com/BishopFox/jsluice/cmd/jsluice@latest"},
    "getJS": {"method": "go", "package": "github.com/003random/getJS/v2@latest", "fallback_wrapper": "getjs"},
    "osv-scanner": {"method": "go", "package": "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"},
    "curlie": {"method": "go", "package": "github.com/rs/curlie@latest"},
    "trivy": {"method": "go", "package": "github.com/aquasecurity/trivy/cmd/trivy@latest"},
    "grype": {"method": "go", "package": "github.com/anchore/grype/cmd/grype@latest"},
    "syft": {"method": "go", "package": "github.com/anchore/syft/cmd/syft@latest"},
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
    for p in [TOOLS_HOME, LOCAL_BIN, GO_BIN, USER_LOCAL_BIN, NPM_HOME, NPM_BIN, SRC_HOME, LOG_DIR]:
        p.mkdir(parents=True, exist_ok=True)


def install_env() -> dict[str, str]:
    ensure_dirs()
    env = dict(os.environ)
    extra = [str(LOCAL_BIN), str(NPM_BIN), str(GO_BIN), str(USER_LOCAL_BIN), str(VENV_BIN)]
    gem_root = Path.home() / ".gem"
    if gem_root.exists():
        extra += [str(x) for x in gem_root.glob("ruby/*/bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env["GOBIN"] = str(LOCAL_BIN)
    env["GOPATH"] = str(Path.home() / "go")
    env["npm_config_prefix"] = str(NPM_HOME)
    return env


def chmod_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def names_for(name: str, binary: str | None = None) -> list[str]:
    return adapter_names_for(name, binary)


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
    return True


def recipe_for(name: str, binary: str | None = None) -> dict[str, Any] | None:
    return RECIPES.get(name) or RECIPES.get(binary or "")


def method_for(name: str, binary: str | None = None) -> str:
    recipe = recipe_for(name, binary)
    return str(recipe.get("method")) if recipe else "safe-adapter"


def run_command(command: list[str], log_path: Path, timeout: int = 1200) -> tuple[bool, int]:
    ensure_dirs()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        try:
            proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=install_env(), timeout=timeout)
            return proc.returncode == 0, int(proc.returncode)
        except subprocess.TimeoutExpired:
            log.write(f"\nTIMEOUT after {timeout}s\n")
            return False, 124
        except Exception as exc:
            log.write(f"\nEXCEPTION: {exc}\n")
            return False, 1


def create_python_wrapper(name: str, lines: list[str]) -> Path:
    ensure_dirs()
    path = LOCAL_BIN / name
    path.write_text("\n".join(["#!/usr/bin/env python3", *lines, ""]), encoding="utf-8")
    chmod_exec(path)
    return path


def symlink_or_copy(found: str, name: str, binary: str | None = None) -> None:
    ensure_dirs()
    src = Path(found)
    chmod_exec(src)
    target = LOCAL_BIN / names_for(name, binary)[0]
    try:
        if target.exists() or target.is_symlink():
            try:
                if target.resolve() == src.resolve():
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
            "data = urllib.request.urlopen(url, timeout=25).read().decode('utf-8', 'ignore')",
            "rows = json.loads(data)",
            "seen = set()",
            "for row in rows:",
            "    for item in str(row.get('name_value', '')).replace('\\\\n', chr(10)).splitlines():",
            "        item = item.strip().lstrip('*.')",
            "        if item and item not in seen:",
            "            seen.add(item); print(item)",
        ])
        return True
    return False


def install_one(name: str, binary: str | None = None, *, yes: bool = True, allow_adapter: bool = True) -> dict[str, Any]:
    ensure_dirs()
    started = time.time()
    binary = binary or name
    before = find_binary(name, binary)
    if before:
        adapter = is_adapter(before)
        return {"tool": name, "binary": binary, "ok": True, "real_tool": not adapter, "adapter": adapter, "status": "already_installed" if not adapter else "safe_adapter_present", "path": before, "seconds": 0.0}

    recipe = recipe_for(name, binary)
    method = method_for(name, binary)
    package = str(recipe.get("package") or "") if recipe else ""
    log_path = LOG_DIR / f"{re.sub(r'[^a-zA-Z0-9_.-]+', '-', name).lower()}.log"
    details = ""

    try:
        if recipe:
            if method == "go":
                go = find_binary("go", "go") or shutil.which("go")
                if not go:
                    install_apt("golang-go", log_path)
                    go = find_binary("go", "go") or shutil.which("go")
                if go:
                    ok, code = run_command([go, "install", package], log_path, timeout=2400)
                    details = f"go_exit={code}; ok={ok}"
                else:
                    details = "go_missing"
            elif method == "pip":
                ok, code = run_command([sys.executable, "-m", "pip", "install", "--upgrade", package], log_path, timeout=1800)
                details = f"pip_exit={code}; ok={ok}"
            elif method == "npm":
                npm = find_binary("npm", "npm") or shutil.which("npm")
                if not npm:
                    install_apt("npm", log_path)
                    npm = find_binary("npm", "npm") or shutil.which("npm")
                if npm:
                    ok, code = run_command([npm, "install", "-g", "--prefix", str(NPM_HOME), package], log_path, timeout=1800)
                    details = f"npm_exit={code}; ok={ok}"
                else:
                    details = "npm_missing"
            elif method == "npm_wrapper":
                npm = find_binary("npm", "npm") or shutil.which("npm")
                if npm:
                    ok, code = run_command([npm, "install", "-g", "--prefix", str(NPM_HOME), package], log_path, timeout=1800)
                    details = f"npm_wrapper_exit={code}; ok={ok}"
                create_python_wrapper(str(recipe.get("wrapper") or binary), [
                    "import shutil, subprocess, sys",
                    "npx = shutil.which('npx')",
                    "if not npx:",
                    "    print('npx not found', file=sys.stderr); raise SystemExit(127)",
                    f"raise SystemExit(subprocess.call([npx, '--yes', {package!r}] + sys.argv[1:]))",
                ])
            elif method == "npm_alias":
                alias_to = str(recipe.get("alias_to") or package)
                install_one(alias_to, alias_to, yes=yes, allow_adapter=allow_adapter)
                found_alias = find_binary(alias_to, alias_to)
                if found_alias:
                    create_python_wrapper(name, ["import subprocess, sys", f"raise SystemExit(subprocess.call([{found_alias!r}] + sys.argv[1:]))"])
                details = f"alias_to={alias_to}"
            elif method == "cargo":
                cargo = find_binary("cargo", "cargo") or shutil.which("cargo")
                if not cargo:
                    install_apt("cargo", log_path)
                    cargo = find_binary("cargo", "cargo") or shutil.which("cargo")
                if cargo:
                    ok, code = run_command([cargo, "install", package], log_path, timeout=2400)
                    details = f"cargo_exit={code}; ok={ok}"
                else:
                    details = "cargo_missing"
            elif method == "gem":
                gem = find_binary("gem", "gem") or shutil.which("gem")
                if not gem:
                    install_apt("ruby", log_path)
                    gem = find_binary("gem", "gem") or shutil.which("gem")
                if gem:
                    ok, code = run_command([gem, "install", "--user-install", package], log_path, timeout=1800)
                    details = f"gem_exit={code}; ok={ok}"
                else:
                    details = "gem_missing"
            elif method == "apt":
                ok, details = install_apt(package, log_path)
            elif method == "git_script":
                repo = str(recipe.get("repo") or "")
                script = str(recipe.get("script") or binary)
                dest = SRC_HOME / name.replace("/", "-")
                if not dest.exists():
                    run_command(["git", "clone", "--depth", "1", repo, str(dest)], log_path, timeout=1800)
                script_path = dest / script
                if script_path.exists():
                    symlink_or_copy(str(script_path), name, binary)
                details = f"git_script={script}"
            elif method == "git_wrapper":
                repo = str(recipe.get("repo") or "")
                script = str(recipe.get("script") or binary)
                dest = SRC_HOME / name.replace("/", "-")
                if not dest.exists():
                    run_command(["git", "clone", "--depth", "1", repo, str(dest)], log_path, timeout=1800)
                script_path = dest / script
                if script_path.exists():
                    create_python_wrapper(binary, ["import subprocess, sys", f"raise SystemExit(subprocess.call([{sys.executable!r}, {str(script_path)!r}] + sys.argv[1:]))"])
                details = f"git_wrapper={script}"
            elif method == "python_wrapper":
                ok = create_builtin_wrapper(str(recipe.get("kind")), name, binary)
                details = f"python_wrapper={recipe.get('kind')}; ok={ok}"

            if str(recipe.get("post") or "") == "zap-wrapper":
                for candidate in [Path("/usr/share/zaproxy/zap-baseline.py"), Path("/usr/bin/zap-baseline.py")]:
                    if candidate.exists():
                        create_python_wrapper("zap-baseline.py", ["import subprocess, sys", f"raise SystemExit(subprocess.call(['python3', {str(candidate)!r}] + sys.argv[1:]))"])
                        break
    except Exception as exc:
        details += f"; exception={str(exc)[:300]}"
        try:
            log_path.write_text(details, encoding="utf-8")
        except Exception:
            pass

    found = find_binary(name, binary)
    if found:
        symlink_or_copy(found, name, binary)
        found = find_binary(name, binary)

    if not found and allow_adapter:
        reason = details or ("no native recipe" if not recipe else "native installer did not expose binary")
        create_safe_adapter(name, binary, reason=reason)
        found = find_binary(name, binary)

    adapter = is_adapter(found)
    return {
        "tool": name,
        "binary": binary,
        "method": method,
        "package": package,
        "ok": bool(found),
        "real_tool": bool(found and not adapter),
        "adapter": bool(adapter),
        "status": "installed_or_repaired" if found and not adapter else "safe_adapter_installed" if found and adapter else "install_failed",
        "path": found,
        "details": details,
        "log": str(log_path),
        "seconds": round(time.time() - started, 2),
    }


def install_missing_from_inventory(rows: list[dict[str, Any]], *, max_install: int = 100, yes: bool = True) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    started = time.time()
    missing = [r for r in rows if not r.get("installed")]
    for index, row in enumerate(missing[:max_install], 1):
        name = str(row.get("name"))
        binary = str(row.get("binary") or name)
        print(f"[{index:03d}/{len(missing):03d}] Installing/checking {name} via {method_for(name, binary)} ...", flush=True)
        result = install_one(name, binary, yes=yes, allow_adapter=True)
        print(f"      status={result.get('status')} ok={result.get('ok')} real={result.get('real_tool')} adapter={result.get('adapter')} path={result.get('path') or '-'} seconds={result.get('seconds')}", flush=True)
        results.append(result)
    return {
        "generated_at": time.time(),
        "summary": {
            "attempted": len(results),
            "installed_or_repaired": len([r for r in results if r.get("ok")]),
            "real_tools": len([r for r in results if r.get("real_tool")]),
            "safe_adapters": len([r for r in results if r.get("adapter")]),
            "failed": len([r for r in results if not r.get("ok")]),
            "seconds": round(time.time() - started, 2),
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Universal VulnScope Top100 installer with safe adapter fallback")
    parser.add_argument("tool", nargs="?")
    parser.add_argument("--binary")
    parser.add_argument("--list-recipes", action="store_true")
    parser.add_argument("--no-adapter", action="store_true")
    args = parser.parse_args()
    if args.list_recipes:
        print(json.dumps({"recipes": sorted(RECIPES), "count": len(RECIPES)}, indent=2))
        return 0
    if not args.tool:
        print(json.dumps({"error": "tool name required unless --list-recipes is used"}, indent=2))
        return 2
    print(json.dumps(install_one(args.tool, args.binary or args.tool, allow_adapter=not args.no_adapter), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
