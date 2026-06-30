#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from target_scope_guard import host_from_target, normalize_target
from tool_doctor_cli import TOP_TOOLS

try:
    from mega_tools_cli import MEGA_TOOLS
except Exception:  # pragma: no cover
    MEGA_TOOLS = []

try:
    from universal_tool_installer import (
        find_binary,
        has_recipe,
        install_missing_from_inventory,
        install_one,
        install_env,
        method_for,
        recipe_for,
    )
except Exception:  # pragma: no cover
    find_binary = None
    has_recipe = None
    install_missing_from_inventory = None
    install_one = None
    install_env = None
    method_for = None
    recipe_for = None

OUT = Path("reports/output/top100-tools")

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
    if install_env:
        e = install_env()
    else:
        e = dict(os.environ)
    e["PYTHONUNBUFFERED"] = "1"
    return e


def slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip("-.").lower() or "target"


def tool_path(name: str, binary: str | None = None) -> str | None:
    if find_binary:
        return find_binary(name, binary or name)
    return None


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
    if any(x in low for x in ["tls", "ssl", "openssl", "testssl"]):
        return "tls_review"
    if any(x in low for x in ["js", "link", "secret", "gitleaks", "truffle", "mantra"]):
        return "client_side_review"
    if any(x in low for x in ["cors", "waf", "whatweb", "builtwith"]):
        return "web_fingerprint"
    if any(x in low for x in ["audit", "trivy", "grype", "syft", "safety", "checkov", "semgrep", "snyk"]):
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
    rows: list[dict[str, Any]] = []
    for index, name in enumerate(TOP_TOOLS[:100], 1):
        meta = mega.get(name, {})
        binary = str(meta.get("binary") or name)
        path = tool_path(name, binary)
        recipe = recipe_for(name, binary) if recipe_for else None
        auto_supported = bool(recipe or (meta and meta.get("type") in {"go", "pipx_or_pip"}))
        method = method_for(name, binary) if method_for else str(meta.get("type") or "manual")
        rows.append({
            "index": index,
            "name": name,
            "binary": binary,
            "category": str(meta.get("category") or infer_category(name)),
            "profile": infer_profile(name),
            "installed": path is not None,
            "path": path,
            "auto_install_supported": auto_supported,
            "install_method": method,
            "safe_runner_available": name in SAFE_RUNNERS,
            "note": "manual-disabled in autonomous mode" if infer_profile(name) == "manual_disabled" else "integrated",
        })
    return rows


def write_status(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = build_inventory()
    payload = {
        "target": target,
        "generated_at": time.time(),
        "summary": {
            "total_integrated": len(rows),
            "installed": len([r for r in rows if r["installed"]]),
            "missing": len([r for r in rows if not r["installed"]]),
            "safe_runners": len([r for r in rows if r["safe_runner_available"]]),
            "auto_install_supported": len([r for r in rows if r["auto_install_supported"]]),
            "auto_installable_missing": len([r for r in rows if not r["installed"] and r["auto_install_supported"]]),
        },
        "tools": rows,
    }
    (OUT / "top100-status.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# VulnScope Top 100 Tool Integration",
        "",
        f"Integrated tools: `{payload['summary']['total_integrated']}`",
        f"Installed now: `{payload['summary']['installed']}`",
        f"Missing now: `{payload['summary']['missing']}`",
        f"Safe runners wired: `{payload['summary']['safe_runners']}`",
        f"Auto-install supported: `{payload['summary']['auto_install_supported']}`",
        f"Auto-installable missing: `{payload['summary']['auto_installable_missing']}`",
        "",
        "## Tool Matrix",
    ]
    for row in rows:
        lines.append(
            f"- `{row['index']:03d}` `{row['name']}` binary=`{row['binary']}` method=`{row['install_method']}` "
            f"category=`{row['category']}` profile=`{row['profile']}` installed=`{row['installed']}` "
            f"runner=`{row['safe_runner_available']}` path=`{row.get('path') or '-'}`"
        )
    (OUT / "top100-status.md").write_text("\n".join(lines), encoding="utf-8")
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
        if not tool_path(name, binary):
            results.append({"tool": name, "status": "missing", "reason": "binary not installed"})
            continue
        output_file = out_dir / f"{slug(name)}.txt"
        command = SAFE_RUNNERS[name].format(target=shlex.quote(target), host=shlex.quote(host), out=shlex.quote(str(output_file)))
        result = run_live(name, command, log_dir / f"{slug(name)}.log", timeout=240)
        result.update({"tool": name, "output_file": str(output_file), "status": "ran" if result.get("ok") else "review"})
        results.append(result)

    probe_command = "python3 safe_param_orchestrator_cli.py --target {target} --max-urls 120 --per-url-limit 4 --families 9 --delay 0.35".format(target=shlex.quote(target))
    probe_result = run_live("adaptive-safe-parameters", probe_command, log_dir / "adaptive-safe-parameters.log", timeout=1800)
    probe_result.update({"tool": "adaptive-safe-parameters", "output_file": "reports/output/safe-canary/safe-probes.json", "status": "ran" if probe_result.get("ok") else "review"})
    results.append(probe_result)

    summary = {
        "target": target,
        "host": host,
        "safe_tools_considered": len([r for r in inventory if r["safe_runner_available"]]) + 1,
        "ran": len([r for r in results if r.get("status") == "ran"]),
        "missing": len([r for r in results if r.get("status") == "missing"]),
        "skipped_controlled": len([r for r in results if r.get("status") == "skipped_controlled"]),
    }
    payload = {"summary": summary, "results": results, "inventory_report": "reports/output/top100-tools/top100-status.md", "safe_parameter_report": "reports/output/safe-canary/safe-probes.md"}
    (run_dir / "top100-integration.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# Top 100 Tool Run — {host}", "", f"Target: `{target}`", f"Ran: `{summary['ran']}`", f"Missing: `{summary['missing']}`", f"Skipped controlled: `{summary['skipped_controlled']}`", "", "## Results"]
    for r in results:
        lines.append(f"- `{r.get('tool')}` status=`{r.get('status')}` output=`{r.get('output_file', 'n/a')}` log=`{r.get('log', 'n/a')}`")
    lines += ["", "## Adaptive Safe Parameters", "- Report: `reports/output/safe-canary/safe-probes.md`"]
    (run_dir / "top100-integration.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def install_supported(max_install: int = 100, yes: bool = False) -> dict[str, Any]:
    rows = build_inventory()
    if install_missing_from_inventory:
        payload = install_missing_from_inventory(rows, max_install=max_install, yes=yes)
    else:
        payload = {"summary": {"attempted": 0, "installed_or_repaired": 0, "failed": 0}, "results": []}
    refreshed = build_inventory()
    payload["summary"]["installed_after"] = len([r for r in refreshed if r["installed"]])
    payload["summary"]["missing_after"] = len([r for r in refreshed if not r["installed"]])
    payload["final_status"] = refreshed
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "top100-install.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    write_status()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Top 100 VulnScope tool integrator: status, universal setup, safe execution wiring")
    parser.add_argument("--target")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--install-supported", action="store_true")
    parser.add_argument("--max-install", type=int, default=100)
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
            "safe_parameters": "reports/output/safe-canary/safe-probes.md",
        },
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
