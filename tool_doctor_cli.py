#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/tool-doctor")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
GO_ROOT = Path.home() / ".vulnscope" / "tools" / "go"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
PIPX_HOME = Path.home() / ".local" / "share" / "pipx" / "venvs"

APT_TOOLS = [
    "curl", "wget", "git", "jq", "whois", "dnsutils", "netcat-openbsd", "nmap", "whatweb", "sslscan", "testssl.sh",
    "python3-pip", "python3-venv", "pipx", "golang", "nodejs", "npm", "parallel", "moreutils",
]
PIP_TOOLS = [
    "httpx", "requests", "beautifulsoup4", "lxml", "pyyaml", "tldextract", "rich", "jinja2", "cryptography", "certifi",
    "dnspython", "python-whois", "waybackpy", "pip-audit", "safety", "semgrep", "wappalyzer", "scrapy", "aiohttp", "yarl",
]
NPM_TOOLS = ["retire", "wappalyzer-cli"]
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx-toolkit": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "asnmap": "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    "mapcidr": "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "uncover": "github.com/projectdiscovery/uncover/cmd/uncover@latest",
    "notify": "github.com/projectdiscovery/notify/cmd/notify@latest",
    "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httprobe": "github.com/tomnomnom/httprobe@latest",
    "unfurl": "github.com/tomnomnom/unfurl@latest",
    "anew": "github.com/tomnomnom/anew@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
    "gf": "github.com/tomnomnom/gf@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "gospider": "github.com/jaeles-project/gospider@latest",
    "github-subdomains": "github.com/gwen001/github-subdomains@latest",
    "github-endpoints": "github.com/gwen001/github-endpoints@latest",
    "gitleaks": "github.com/gitleaks/gitleaks/v8@latest",
    "trufflehog": "github.com/trufflesecurity/trufflehog/v3@latest",
    "mantra": "github.com/MrEmpy/mantra@latest",
}

BASE_CHECKS = [
    "python3", "python", "pip", "pipx", "git", "curl", "wget", "jq", "whois", "dig", "host", "nslookup", "openssl", "sslscan", "testssl.sh",
    "nmap", "whatweb", "node", "npm", "go", "parallel", "sponge", "semgrep", "safety", "pip-audit", "retire", "wappalyzer",
    "subfinder", "httpx", "dnsx", "tlsx", "naabu", "katana", "nuclei", "asnmap", "mapcidr", "uncover", "notify", "interactsh-client",
    "gau", "waybackurls", "assetfinder", "httprobe", "unfurl", "anew", "qsreplace", "gf", "hakrawler", "gospider", "github-subdomains", "github-endpoints",
    "gitleaks", "trufflehog", "mantra", "xnLinkFinder", "linkfinder", "graphw00f", "ffuf", "feroxbuster", "gobuster", "amass", "sublist3r", "massdns",
    "dnsrecon", "dnsenum", "theHarvester", "crtsh", "cewl", "arjun", "paramspider", "uro", "dalfox", "kxss", "kxss-py", "jsluice",
    "getJS", "SecretFinder", "LinkFinder", "git-dumper", "git-secrets", "detect-secrets", "checkov", "trivy", "grype", "syft", "osv-scanner",
    "npm-audit", "yarn", "pnpm", "cargo", "cargo-audit", "bundler-audit", "retire-js", "cyclonedx-py", "snyk", "zap-baseline.py", "zap-full-scan.py",
    "nikto", "wapiti", "lynis", "httpie", "xh", "curlie", "mitmproxy", "burpsuite", "chromium", "google-chrome", "firefox", "chromedriver",
]

CAPABILITY_SLOTS = [
    "scope-policy", "authorization-audit", "robots-check", "securitytxt-check", "sitemap-collector", "dns-snapshot", "subdomain-passive", "certificate-transparency", "archive-url-map", "crawler-map",
    "javascript-map", "endpoint-extractor", "parameter-map", "header-audit", "tls-audit", "cookie-audit", "cors-audit", "redirect-audit", "form-audit", "login-surface-map",
    "account-diff-reader", "role-surface-map", "api-surface-map", "graphql-surface-map", "object-route-map", "public-storage-reference", "cloud-reference", "dependency-hint", "version-hint", "package-integrity-hint",
    "secret-pattern-redacted", "verbose-error-audit", "cache-policy-audit", "rate-limit-evidence", "history-diff", "asset-graph", "evidence-normalizer", "evidence-card", "reportability-rank", "final-verdict",
]

TOOLS: dict[str, dict[str, Any]] = {}
for binary in BASE_CHECKS:
    TOOLS[binary] = {"binary": binary, "category": "safe helper availability", "install": [], "aliases": [binary], "optional": True}
for name, pkg in GO_TOOLS.items():
    TOOLS[name] = {"binary": name.replace("httpx-toolkit", "httpx"), "category": "safe Go helper", "install": [["go", "install", pkg]], "aliases": [name, name.replace("httpx-toolkit", "httpx")], "optional": True}
TOOLS.update({
    "linkfinder": {"binary": "linkfinder", "category": "local JS endpoint extraction", "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "git+https://github.com/GerbenJavado/LinkFinder.git"]], "aliases": ["linkfinder", "LinkFinder", "linkfinder.py", "LinkFinder.py"], "optional": True, "wrapper": "python3 -m linkfinder \"$@\""},
    "graphw00f": {"binary": "graphw00f", "category": "GraphQL review helper", "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "graphw00f"]], "aliases": ["graphw00f", "Graphw00f", "graphw00f.py"], "optional": True, "wrapper": "python3 -m graphw00f \"$@\""},
    "xnLinkFinder": {"binary": "xnLinkFinder", "category": "local JS endpoint extraction", "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "xnLinkFinder"]], "aliases": ["xnLinkFinder", "xnlinkfinder", "xnlinkfinder.py"], "optional": True, "wrapper": "python3 -m xnLinkFinder \"$@\""},
})
for slot in CAPABILITY_SLOTS:
    TOOLS["capability-" + slot] = {"binary": "capability-" + slot, "category": "built-in VulnScope capability", "install": [], "aliases": [], "optional": True, "virtual": True}


def env() -> dict[str, str]:
    e = dict(os.environ)
    extra = [str(LOCAL_BIN), str(GO_ROOT / "bin"), str(GO_BIN), str(USER_LOCAL_BIN)]
    e["PATH"] = os.pathsep.join(extra + [e.get("PATH", "")])
    e["GOBIN"] = str(LOCAL_BIN)
    e["GOPATH"] = str(Path.home() / "go")
    return e


def go_command() -> str | None:
    return shutil.which("go") or (str(GO_ROOT / "bin" / "go") if (GO_ROOT / "bin" / "go").exists() else None)


def chmod(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def candidates(tool: dict[str, Any]) -> list[Path]:
    names = list(dict.fromkeys([tool["binary"], *tool.get("aliases", [])]))
    roots = [LOCAL_BIN, GO_BIN, USER_LOCAL_BIN, GO_ROOT / "bin", PIPX_HOME, Path.home() / ".local" / "share", Path.home() / "go"]
    out: list[Path] = []
    for name in names:
        found = shutil.which(name, path=env().get("PATH"))
        if found:
            out.append(Path(found))
    wanted = {n.lower() for n in names}
    for root in roots:
        if not root.exists():
            continue
        for name in names:
            p = root / name
            if p.exists() and p.is_file():
                out.append(p)
        try:
            for p in root.rglob("*"):
                if p.is_file() and p.name.lower() in wanted:
                    out.append(p)
        except Exception:
            pass
    return list(dict.fromkeys(out))


def link_found(tool: dict[str, Any]) -> str | None:
    if tool.get("virtual"):
        return "built-in"
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    for p in candidates(tool):
        chmod(p)
        target = LOCAL_BIN / tool["binary"]
        if not target.exists():
            try:
                target.symlink_to(p)
            except Exception:
                try:
                    shutil.copy2(p, target)
                except Exception:
                    pass
        chmod(target)
        return str(target if target.exists() else p)
    return None


def write_wrapper(tool: dict[str, Any]) -> str | None:
    wrapper = tool.get("wrapper")
    if not wrapper:
        return None
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    target = LOCAL_BIN / tool["binary"]
    if target.exists():
        return str(target)
    target.write_text("#!/usr/bin/env bash\n" + wrapper + "\n", encoding="utf-8")
    chmod(target)
    return str(target)


def run(command: list[str]) -> dict[str, Any]:
    actual = list(command)
    if actual and actual[0] == "go":
        go = go_command()
        if not go:
            return {"command": command, "ok": False, "error": "go is not installed"}
        actual[0] = go
    started = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "tool-doctor-install.log").open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(actual) + "\n")
        try:
            p = subprocess.run(actual, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200, env=env())
            log.write(p.stdout[-6000:])
            return {"command": actual, "ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - started, 2), "tail": p.stdout[-1000:]}
        except Exception as exc:
            log.write(str(exc))
            return {"command": actual, "ok": False, "error": str(exc), "seconds": round(time.time() - started, 2)}


def install_foundations() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if shutil.which("apt-get"):
        results.append(run(["bash", "-lc", "sudo apt-get update -y && sudo apt-get install -y " + " ".join(APT_TOOLS)]))
    results.append(run([sys.executable, "-m", "pip", "install", "--user", "--upgrade", *PIP_TOOLS]))
    if shutil.which("npm"):
        results.append(run(["bash", "-lc", "npm install -g " + " ".join(NPM_TOOLS)]))
    return results


def doctor_one(name: str, install: bool) -> dict[str, Any]:
    tool = TOOLS[name]
    before = link_found(tool)
    installs = []
    if not before and install:
        for command in tool.get("install", []):
            res = run(command)
            installs.append(res)
            after_attempt = link_found(tool)
            if after_attempt:
                break
    after = link_found(tool)
    wrapper = None
    if not after:
        wrapper = write_wrapper(tool)
        after = link_found(tool) or wrapper
    return {"name": name, "binary": tool.get("binary"), "category": tool.get("category"), "optional": tool.get("optional", True), "virtual": tool.get("virtual", False), "installed_before": bool(before), "installed_after": bool(after), "path": after, "install_attempts": installs, "wrapper_created": bool(wrapper)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair and inventory top safe VulnScope helper tools and built-in capabilities")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--tools", nargs="*", default=list(TOOLS))
    parser.add_argument("--top", type=int, default=100)
    args = parser.parse_args()
    if args.install and not args.yes:
        ans = input("Install/repair optional user-local helper tools? type YES: ").strip()
        if ans != "YES":
            print(json.dumps({"started": False, "reason": "confirmation not provided"}, indent=2))
            return 1
    OUT.mkdir(parents=True, exist_ok=True)
    foundations = install_foundations() if args.install else []
    names = [n for n in args.tools if n in TOOLS][: max(1, args.top)]
    rows = [doctor_one(n, args.install) for n in names]
    summary = {"requested": len(rows), "installed_or_builtin": len([r for r in rows if r["installed_after"]]), "missing_optional": len([r for r in rows if not r["installed_after"]]), "physical_tools": len([r for r in rows if not r.get("virtual")]), "builtin_capabilities": len([r for r in rows if r.get("virtual")])}
    payload = {"summary": summary, "foundation_installs": foundations, "tools": rows, "path_hint": f"export PATH='{LOCAL_BIN}:{GO_ROOT / 'bin'}:{GO_BIN}:{USER_LOCAL_BIN}:$PATH'"}
    (OUT / "tool-doctor.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Tool Doctor - Top Safe 100", "", f"Requested: `{summary['requested']}`", f"Installed or built-in: `{summary['installed_or_builtin']}`", f"Physical tools: `{summary['physical_tools']}`", f"Built-in capabilities: `{summary['builtin_capabilities']}`", f"Missing optional: `{summary['missing_optional']}`", "", "## Tools / Capabilities"]
    for r in rows:
        lines.append(f"- `{r['name']}` binary=`{r.get('binary')}` category=`{r.get('category')}` installed=`{r['installed_after']}` path=`{r.get('path')}` builtin=`{r.get('virtual')}`")
    lines += ["", "## PATH", "```bash", payload["path_hint"], "```"]
    (OUT / "tool-doctor.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"summary": summary, "report": "reports/output/tool-doctor/tool-doctor.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
