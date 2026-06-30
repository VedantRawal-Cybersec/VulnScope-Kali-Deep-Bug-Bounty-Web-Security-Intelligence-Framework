#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from target_scope_guard import host_from_target, normalize_target
from tool_doctor_cli import TOP_TOOLS

try:
    from mega_tools_cli import MEGA_TOOLS, as_tool
    from arsenal.installer import install_tool, is_installed
except Exception:  # pragma: no cover - integration fallback
    MEGA_TOOLS = []
    as_tool = None
    install_tool = None
    is_installed = None

OUT = Path("reports/output/top100-tools")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"

SAFE_RUNNERS = {
    "subfinder": "subfinder -d {host} -silent -o {out}",
    "assetfinder": "assetfinder --subs-only {host} > {out}",
    "amass": "amass enum -passive -d {host} -o {out}",
    "gau": "gau {host} > {out}",
    "waybackurls": "printf '%s\n' {host} | waybackurls > {out}",
    "httpx": "printf '%s\n' {target} | httpx -silent -status-code -title -tech-detect -follow-redirects -no-color -o {out}",
    "katana": "katana -u {target} -d 2 -silent -jc -o {out}",
    "dnsx": "printf '%s\n' {host} | dnsx -silent -a -resp -o {out}",
    "tlsx": "printf '%s\n' {host} | tlsx -silent -tls-probe -o {out}",
    "wafw00f": "wafw00f {target} --no-colors > {out}",
    "whatweb": "whatweb --no-errors --color=never {target} > {out}",
    "nuclei": "nuclei -u {target} -tags exposure,misconfig,headers,ssl -severity info,low,medium -rate-limit 3 -retries 0 -silent -o {out}",
}

CONTROLLED_SAFE = {"httpx", "katana", "dnsx", "tlsx", "wafw00f", "whatweb", "nuclei"}


def env() -> dict[str, str]:
    e = dict(os.environ)
    e["PATH"] = os.pathsep.join([str(LOCAL_BIN), str(GO_BIN), str(USER_LOCAL_BIN), e.get("PATH", "")])
    e["PYTHONUNBUFFERED"] = "1"
    return e


def slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip("-.").lower() or "target"


def tool_path(binary: str) -> str | None:
    return shutil.which(binary, path=env().get("PATH"))


def mega_map() -> dict[str, dict[str, Any]]:
    return {str(item.get("name")): item for item in MEGA_TOOLS if isinstance(item, dict)}


def infer_category(name: str) -> str:
    low = name.lower()
    if any(x in low for x in ["sub", "asset", "amass", "asn", "chaos"]):
        return "asset_discovery"
    if any(x in low for x in ["gau", "wayback", "katana", "hakrawler", "gospider"]):
        return "url_and_crawl"
    if any(x in low for x in ["dns", "host", "dig", "nslookup"]):
        return "dns_review"
    if any(x in low for x in ["tls", "ssl", "openssl"]):
        return "tls_review"
    if any(x in low for x in ["js", "link", "secret", "gitleaks", "truffle"]):
        return "client_side_review"
    if any(x in low for x in ["cors", "waf", "whatweb", "builtwith"]):
        return "web_fingerprint"
    if any(x in low for x in ["audit", "trivy", "grype", "syft", "safety", "checkov", "semgrep"]):
        return "local_dependency_review"
    return "support_tool"


def infer_profile(name: str) -> str:
    low = name.lower()
    disabled_words = ["ffuf", "gobuster", "ferox", "dirsearch", "dalfox", "nikto", "wapiti", "zap", "nmap", "naabu"]
    if any(x in low for x in disabled_words):
        return "manual_disabled"
    if name in SAFE_RUNNERS:
        return "safe_runner"
    if any(x in low for x in ["audit", "semgrep", "trivy", "grype", "syft", "secret", "jq", "unfurl", "uro", "anew", "gf"]):
        return "local_only"
    return "integrated_inventory"


def build_inventory() -> list[dict[str, Any]]:
    mega = mega_map()
    rows = []
    for index, name in enumerate(TOP_TOOLS[:100], 1):
        meta = mega.get(name, {})
        binary = str(meta.get("binary") or name)
        installed = tool_path(binary) is not None
        rows.append({
            "index": index,
            "name": name,
            "binary": binary,
            "category": str(meta.get("category") or infer_category(name)),
            "profile": infer_profile(name),
            "installed": installed,
            "path": tool_path(binary),
            "auto_install_supported": bool(meta and meta.get("type") in {"go", "pipx_or_pip"}),
            "safe_runner_available": name in SAFE_RUNNERS,
            "note": "manual-disabled in autonomous mode" if infer_profile(name) == "manual_disabled" else "integrated",
        })
    return rows


def write_status(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = build_inventory()
    status_path = OUT / "top100-status.json"
    md_path = OUT / "top100-status.md"
    payload = {
        "target": target,
        "generated_at": time.time(),
        "summary": {
            "total_integrated": len(rows),
            "installed": len([r for r in rows if r["installed"]]),
            "missing": len([r for r in rows if not r["installed"]]),
            "safe_runners": len([r for r in rows if r["safe_runner_available"]]),
            "auto_install_supported": len([r for r in rows if r["auto_install_supported"]]),
        },
        "tools": rows,
    }
    status_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# VulnScope Top 100 Tool Integration",
        "",
        f"Integrated tools: `{payload['summary']['total_integrated']}`",
        f"Installed now: `{payload['summary']['installed']}`",
        f"Missing now: `{payload['summary']['missing']}`",
        f"Safe runners wired: `{payload['summary']['safe_runners']}`",
        f"Auto-install supported: `{payload['summary']['auto_install_supported']}`",
        "",
        "## Tool Matrix",
    ]
    for row in rows:
        lines.append(f"- `{row['index']:03d}` `{row['name']}` category=`{row['category']}` profile=`{row['profile']}` installed=`{row['installed']}` runner=`{row['safe_runner_available']}`")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return payload


def reader(stream: Any, q: "queue.Queue[str]") -> None:
    try:
        for line in iter(stream.readline, ""):
            q.put(line)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def run_live(label: str, command: str, log_path: Path, timeout: int = 180) -> dict[str, Any]:
    started = time.time()
    q: "queue.Queue[str]" = queue.Queue()
    output: list[str] = []
    print(f"[top100] running {label}: {command}", flush=True)
    try:
        proc = subprocess.Popen(["bash", "-lc", command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, env=env())
    except Exception as exc:
        return {"ok": False, "label": label, "error": str(exc), "seconds": 0}
    if proc.stdout is not None:
        threading.Thread(target=reader, args=(proc.stdout, q), daemon=True).start()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", errors="ignore") as log:
        log.write("$ " + command + "\n")
        last = time.time()
        while proc.poll() is None:
            while True:
                try:
                    line = q.get_nowait()
                except queue.Empty:
                    break
                output.append(line)
                output = output[-200:]
                log.write(line)
                log.flush()
            elapsed = int(time.time() - started)
            if time.time() - last >= 5:
                print(f"[top100-working] {label} elapsed={elapsed}s log={log_path}", flush=True)
                last = time.time()
            if elapsed > timeout:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return {"ok": False, "timeout": True, "label": label, "seconds": round(time.time() - started, 2), "log": str(log_path), "tail": "".join(output)[-1500:]}
            time.sleep(0.1)
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "label": label, "seconds": round(time.time() - started, 2), "log": str(log_path), "tail": "".join(output)[-1500:]}


def run_safe_tools(target: str, include_controlled: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    run_dir = OUT / slug(host)
    out_dir = run_dir / "outputs"
    log_dir = run_dir / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    inventory = build_inventory()
    results = []
    for row in inventory:
        name = row["name"]
        binary = row["binary"]
        if name not in SAFE_RUNNERS:
            continue
        if name in CONTROLLED_SAFE and not include_controlled:
            results.append({"tool": name, "status": "skipped_controlled", "reason": "run again with --include-controlled"})
            continue
        if not tool_path(binary):
            results.append({"tool": name, "status": "missing", "reason": "binary not installed"})
            continue
        output_file = out_dir / f"{slug(name)}.txt"
        command = SAFE_RUNNERS[name].format(target=shlex.quote(target), host=shlex.quote(host), out=shlex.quote(str(output_file)))
        result = run_live(name, command, log_dir / f"{slug(name)}.log", timeout=240)
        result.update({"tool": name, "output_file": str(output_file), "status": "ran" if result.get("ok") else "review"})
        results.append(result)
    summary = {
        "target": target,
        "host": host,
        "safe_tools_considered": len([r for r in inventory if r["safe_runner_available"]]),
        "ran": len([r for r in results if r.get("status") == "ran"]),
        "missing": len([r for r in results if r.get("status") == "missing"]),
        "skipped_controlled": len([r for r in results if r.get("status") == "skipped_controlled"]),
    }
    payload = {"summary": summary, "results": results, "inventory_report": "reports/output/top100-tools/top100-status.md"}
    (run_dir / "top100-integration.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# Top 100 Tool Run — {host}", "", f"Target: `{target}`", f"Ran: `{summary['ran']}`", f"Missing: `{summary['missing']}`", f"Skipped controlled: `{summary['skipped_controlled']}`", "", "## Results"]
    for r in results:
        lines.append(f"- `{r.get('tool')}` status=`{r.get('status')}` output=`{r.get('output_file', 'n/a')}` log=`{r.get('log', 'n/a')}`")
    (run_dir / "top100-integration.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def install_supported(max_install: int = 25, yes: bool = False) -> dict[str, Any]:
    rows = build_inventory()
    installed = []
    skipped = []
    mega = mega_map()
    count = 0
    for row in rows:
        if row["installed"]:
            skipped.append({"tool": row["name"], "status": "already_installed"})
            continue
        meta = mega.get(row["name"])
        if not meta or not row["auto_install_supported"] or not install_tool or not as_tool:
            skipped.append({"tool": row["name"], "status": "not_auto_install_supported"})
            continue
        if count >= max_install:
            skipped.append({"tool": row["name"], "status": "max_install_limit_reached"})
            continue
        ok = install_tool(as_tool(meta), yes=yes, allow_system=False)
        count += 1
        installed.append({"tool": row["name"], "ok": bool(ok)})
    payload = {"summary": {"attempted": count, "installed_or_repaired": len([x for x in installed if x["ok"]]), "skipped": len(skipped)}, "installed": installed, "skipped": skipped}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "top100-install.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Top 100 VulnScope tool integrator: status, safe setup, safe execution wiring")
    parser.add_argument("--target")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--install-supported", action="store_true")
    parser.add_argument("--max-install", type=int, default=25)
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--run-safe", action="store_true")
    parser.add_argument("--include-controlled", action="store_true")
    args = parser.parse_args()

    status = write_status(args.target)
    install = install_supported(max_install=args.max_install, yes=args.yes) if args.install_supported else None
    run = run_safe_tools(args.target, include_controlled=args.include_controlled) if args.run_safe and args.target else None
    print(json.dumps({
        "status": status["summary"],
        "install": install["summary"] if install else "not_requested",
        "run": run["summary"] if run else "not_requested",
        "reports": {
            "status": "reports/output/top100-tools/top100-status.md",
            "install": "reports/output/top100-tools/top100-install.json",
            "run_dir": f"reports/output/top100-tools/{slug(host_from_target(args.target))}" if args.target else "n/a",
        },
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
