#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/tool-doctor")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"

# This registry keeps the old "top 100" visibility, but the live autonomous
# run does not perform sudo/system installs. System-level tools are inventoried
# and reported as optional so the scanner never freezes at a password prompt.
TOP_TOOLS = [
    "python3", "python", "pip", "git", "curl", "wget", "jq", "whois", "dig", "host", "nslookup", "openssl",
    "sslscan", "testssl.sh", "nmap", "whatweb", "node", "npm", "go", "parallel", "sponge", "semgrep", "safety",
    "pip-audit", "retire", "wappalyzer", "subfinder", "httpx", "dnsx", "tlsx", "naabu", "katana", "nuclei",
    "asnmap", "mapcidr", "uncover", "notify", "gau", "waybackurls", "assetfinder", "httprobe", "unfurl", "anew",
    "qsreplace", "gf", "hakrawler", "gospider", "github-subdomains", "github-endpoints", "gitleaks", "trufflehog",
    "mantra", "xnLinkFinder", "linkfinder", "graphw00f", "ffuf", "feroxbuster", "gobuster", "amass", "sublist3r",
    "massdns", "dnsrecon", "dnsenum", "theHarvester", "crtsh", "arjun", "paramspider", "uro", "dalfox", "kxss",
    "jsluice", "getJS", "SecretFinder", "LinkFinder", "git-secrets", "detect-secrets", "checkov", "trivy", "grype",
    "syft", "osv-scanner", "npm-audit", "yarn", "pnpm", "cargo", "cargo-audit", "bundler-audit", "retire-js",
    "cyclonedx-py", "snyk", "zap-baseline.py", "nikto", "wapiti", "lynis", "httpie", "xh", "curlie", "mitmproxy",
    "burpsuite", "chromium", "google-chrome", "firefox", "chromedriver",
]

PYTHON_DEPS: dict[str, str] = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "tldextract": "tldextract",
    "rich": "rich",
    "jinja2": "Jinja2",
    "dns": "dnspython",
    "aiohttp": "aiohttp",
    "yarl": "yarl",
}

SAFE_INSTALL_NOTE = "no_sudo_live_mode"


def env() -> dict[str, str]:
    e = dict(os.environ)
    e["PATH"] = os.pathsep.join([str(LOCAL_BIN), str(GO_BIN), str(USER_LOCAL_BIN), e.get("PATH", "")])
    e["PYTHONUNBUFFERED"] = "1"
    return e


def binary_exists(name: str) -> bool:
    return shutil.which(name, path=env().get("PATH")) is not None


def module_exists(module: str) -> bool:
    try:
        p = subprocess.run([sys.executable, "-c", f"import {module}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        return p.returncode == 0
    except Exception:
        return False


def run_live(command: list[str], timeout: int = 180) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    log_path = OUT / "tool-doctor-install.log"
    started = time.time()
    print(f"[command] {' '.join(command)}", flush=True)
    print(f"[log] {log_path}", flush=True)
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env())
    except Exception as exc:
        return {"ok": False, "error": str(exc), "seconds": 0}

    tail: list[str] = []
    with log_path.open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        while proc.poll() is None:
            if proc.stdout is not None:
                line = proc.stdout.readline()
                if line:
                    tail.append(line)
                    tail = tail[-40:]
                    log.write(line)
                    log.flush()
                    print(line.rstrip()[:180], flush=True)
            if time.time() - started > timeout:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return {"ok": False, "timeout": True, "seconds": round(time.time() - started, 2), "tail": "".join(tail)[-1500:]}
            time.sleep(0.05)
        if proc.stdout is not None:
            rest = proc.stdout.read()
            if rest:
                log.write(rest)
                tail.append(rest)
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "seconds": round(time.time() - started, 2), "tail": "".join(tail)[-1500:]}


def repair_python_deps(install: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for module, package in PYTHON_DEPS.items():
        before = module_exists(module)
        row: dict[str, Any] = {"name": package, "module": module, "kind": "python", "installed_before": before, "installed_after": before, "action": "already_available" if before else "missing"}
        if install and not before:
            print(f"\n[python-dep] installing/checking {package}", flush=True)
            result = run_live([sys.executable, "-m", "pip", "install", "--upgrade", package], timeout=180)
            after = module_exists(module)
            row.update({"installed_after": after, "action": "installed" if after else "install_failed_or_skipped", "install_result": result})
        rows.append(row)
    return rows


def inventory_top_tools(limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in TOP_TOOLS[: max(1, limit)]:
        installed = binary_exists(name)
        rows.append({
            "name": name,
            "kind": "binary_or_external_helper",
            "installed": installed,
            "path": shutil.which(name, path=env().get("PATH")),
            "action": "available" if installed else "optional_missing_no_sudo_autoinstall",
        })
    return rows


def write_reports(payload: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "tool-doctor.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# VulnScope Tool Doctor",
        "",
        "Mode: `visible-no-sudo-non-blocking`",
        f"Checked top tools: `{payload['summary']['checked_top_tools']}`",
        f"External helpers available: `{payload['summary']['external_available']}`",
        f"External helpers missing optional: `{payload['summary']['external_missing_optional']}`",
        f"Python deps available: `{payload['summary']['python_deps_available']}`",
        "",
        "## Important Runtime Fix",
        "- Tool Doctor no longer calls sudo during the autonomous scan.",
        "- Missing external tools are reported as optional instead of blocking the scan.",
        "- Python dependencies are repaired through the active Python environment only.",
        "",
        "## Python Dependencies",
    ]
    for row in payload["python_deps"]:
        lines.append(f"- `{row['name']}` module=`{row['module']}` installed=`{row['installed_after']}` action=`{row['action']}`")
    lines += ["", "## Top Tool Inventory"]
    for row in payload["top_tools"]:
        lines.append(f"- `{row['name']}` installed=`{row['installed']}` action=`{row['action']}` path=`{row.get('path')}`")
    lines += ["", "## PATH", "```bash", f"export PATH='{LOCAL_BIN}:{GO_BIN}:{USER_LOCAL_BIN}:$PATH'", "```"]
    (OUT / "tool-doctor.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Visible, non-blocking VulnScope helper inventory and safe dependency repair")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--tools", nargs="*", default=[])
    parser.add_argument("--top", type=int, default=100)
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    print("=" * 72, flush=True)
    print("VULNSCOPE TOOL DOCTOR — visible, no-sudo, non-blocking", flush=True)
    print("System/helper binaries are inventoried only. No password prompt will block the scan.", flush=True)
    print("=" * 72, flush=True)

    python_rows = repair_python_deps(args.install)
    top_rows = inventory_top_tools(args.top)
    external_available = len([r for r in top_rows if r["installed"]])
    payload = {
        "summary": {
            "checked_top_tools": len(top_rows),
            "external_available": external_available,
            "external_missing_optional": len(top_rows) - external_available,
            "python_deps_available": len([r for r in python_rows if r["installed_after"]]),
            "mode": SAFE_INSTALL_NOTE,
        },
        "python_deps": python_rows,
        "top_tools": top_rows,
        "path_hint": f"export PATH='{LOCAL_BIN}:{GO_BIN}:{USER_LOCAL_BIN}:$PATH'",
    }
    write_reports(payload)
    print(json.dumps({"summary": payload["summary"], "report": "reports/output/tool-doctor/tool-doctor.md", "log": "reports/output/tool-doctor/tool-doctor-install.log"}, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
