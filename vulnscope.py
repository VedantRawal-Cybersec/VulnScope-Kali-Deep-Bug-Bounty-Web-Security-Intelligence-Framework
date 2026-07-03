#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from vulnscope_preflight import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, print_preflight_status, run_preflight

VERSION = "1.10.1-dashboard-counters-fixed"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                         VulnScope Ultimate                       ║
║ Agents → Ollama Gateway → Reasoning Stream → Evidence → Report    ║
╚════════════════════════════════════════════════════════════════════╝
"""


def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        raise ValueError("target is required")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = (parsed.hostname or parsed.netloc or "").split(":")[0].lower().strip()
    if not host:
        raise ValueError("invalid target")
    return host


def run(label: str, command: list[str], timeout: int = 3600) -> dict:
    print(f"\n[{label}]", flush=True)
    print("$ " + " ".join(command), flush=True)
    started = datetime.now(timezone.utc)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, env=env)
        try:
            exit_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_code = proc.wait(timeout=10)
            return {"label": label, "ok": False, "exit_code": exit_code, "command": command, "error": f"timeout after {timeout}s", "started_at": started.isoformat()}
        return {"label": label, "ok": exit_code == 0, "exit_code": exit_code, "command": command, "started_at": started.isoformat(), "ended_at": datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        print(f"error: {exc}", flush=True)
        return {"label": label, "ok": False, "error": str(exc), "command": command, "started_at": started.isoformat()}


def confirm(target: str, yes: bool, scan_mode: str) -> None:
    print("\nAuthorized use only. Scope is locked to the target you provide.")
    print(f"Target: {target}")
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        print("\nRules:")
        print("- You own this target or have explicit written authorization.")
        print("- VulnScope runs evidence-first defensive checks only.")
        print("- Production data modification is not allowed.")
        answer = input("\nType YES to confirm authorization: ").strip()
        if answer != "YES":
            raise SystemExit("Authorization not confirmed.")
    if scan_mode == "safe-active" and not yes and os.getenv("VULNSCOPE_SAFE_ACTIVE_OK", "0") != "1":
        answer = input("\nSafe Active Mode sends harmless canary values to safe GET parameters. Type CONTINUE to proceed: ").strip()
        if answer != "CONTINUE":
            raise SystemExit("Safe Active Mode not confirmed.")
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host_from_target(target), "scan_mode": scan_mode, "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def final_summary(target: str, history: list[dict]) -> None:
    host = host_from_target(target)
    reports = {
        "preflight": "reports/output/vulnscope-main/preflight.md",
        "autonomous_report": f"reports/output/cai-superior/{host}/autonomous-scan-report.md",
        "autonomous_report_json": f"reports/output/cai-superior/{host}/autonomous-scan-report.json",
        "autonomous_state": f"reports/output/cai-superior/{host}/autonomous-scan-state.json",
        "parameter_inventory_v2": f"reports/output/cai-superior/{host}/parameter-inventory-v2.json",
        "evidence_index": f"reports/output/cai-superior/{host}/evidence/evidence-index.md",
        "agent_trace": f"reports/output/cai-superior/{host}/agent-trace.md",
        "agent_registry": f"reports/output/cai-superior/{host}/agent-registry.md",
        "tool_matrix": f"reports/output/cai-superior/{host}/tool-matrix.md",
        "cli_final_dashboard": f"reports/output/cai-superior/{host}/cli-final-dashboard.md",
        "authorization": str(AUTH),
    }
    payload = {"target": target, "history": history, "reports": reports, "generated_at": datetime.now(timezone.utc).isoformat(), "interface": "kali_cli", "cai_style_agents": True, "stable_dashboard": True, "ollama_diagnostics": True, "resume_supported": True, "evidence_store": True, "request_budget": True, "website_dashboard": False}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "final-summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Summary", "", f"Target: `{target}`", "", "CAI-style agents: `true`", "Stable dashboard: `true`", "Ollama diagnostics/fallback: `true`", "Evidence store: `true`", "Request budget: `true`", "Website dashboard: `false`", "", "## Steps"]
    for item in history:
        lines.append(f"- `{item.get('label')}` ok=`{item.get('ok')}` exit=`{item.get('exit_code', 'n/a')}`")
    lines += ["", "## Reports"]
    for name, path in reports.items():
        lines.append(f"- `{name}`: `{path}`")
    (OUT / "final-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\nOpen reports:")
    for path in reports.values():
        print("- " + path)


def append_headers(cmd: list[str], headers: list[str]) -> None:
    for header in headers or []:
        if ":" in header:
            cmd.extend(["--header", header])


def run_agentic(target: str, args: argparse.Namespace) -> dict:
    os.environ["VULNSCOPE_OLLAMA_MODEL"] = args.ollama_model
    os.environ["VULNSCOPE_OLLAMA_URL"] = args.ollama_url
    history: list[dict] = []
    engine_cmd = [sys.executable, "-m", "core.autonomous_scan_engine", "--target", target, "--scan-mode", args.scan_mode, "--max-pages", str(args.max_pages), "--max-depth", str(args.max_depth), "--max-params", str(args.max_params), "--request-timeout", str(args.request_timeout), "--delay", str(args.delay), "--request-budget", str(args.request_budget), "--max-actions", str(args.max_actions), "--ollama-url", args.ollama_url, "--ollama-model", args.ollama_model]
    if args.include_subdomains:
        engine_cmd.append("--include-subdomains")
    if args.resume:
        engine_cmd.append("--resume")
    if args.browser:
        engine_cmd.append("--browser")
    if args.no_live_dashboard:
        engine_cmd.append("--no-live-dashboard")
    append_headers(engine_cmd, args.header)
    history.append(run("CAI-Style Autonomous Scan Engine", engine_cmd, timeout=3600))
    if not args.skip_100_tools:
        orch_cmd = [sys.executable, "-m", "core.tool_orchestrator", "--target", target, "--scan-mode", args.scan_mode, "--criticality", args.criticality, "--tool-timeout", str(args.tool_timeout)]
        if args.include_subdomains:
            orch_cmd.append("--include-subdomains")
        if args.no_live_dashboard:
            orch_cmd.append("--no-live-dashboard")
        history.append(run("Live 100-Tool Safe Orchestrator", orch_cmd, timeout=3600))
    if not args.skip_react:
        cmd = [sys.executable, "-m", "core.react_loop", "--target", target, "--max-turns", str(args.max_turns), "--criticality", args.criticality]
        if args.include_subdomains:
            cmd.append("--include-subdomains")
        if args.force:
            cmd.append("--force")
        if not args.no_live_dashboard:
            cmd.append("--live-dashboard")
        if args.no_final_dashboard:
            cmd.append("--no-final-dashboard")
        history.append(run("Live Autonomous ReAct Loop", cmd, timeout=3600))
    ok = all(item.get("ok") for item in history)
    return {"label": "VulnScope 1.10.1 Dashboard Counter Fix", "ok": ok, "exit_code": 0 if ok else 1, "steps": history}


def run_cai(target: str, args: argparse.Namespace) -> dict:
    cmd = [sys.executable, "cai_superior_cli.py", "--target", target, "--criticality", args.criticality]
    if args.include_subdomains:
        cmd.append("--include-subdomains")
    return run("CAI checkpoint pipeline", cmd, timeout=3600)


def run_preflight_step(args: argparse.Namespace) -> dict:
    payload = run_preflight(install_python=not args.no_python_install, run_tool_setup_flag=not args.skip_tool_setup, check_ollama_flag=not args.skip_ollama, require_ollama=False, auto_pull_model=not args.no_model_pull, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    print_preflight_status(payload)
    return {"label": "Preflight", "ok": bool(payload.get("ok")), "exit_code": 0 if payload.get("ok") else 2, "summary": payload.get("summary", {}), "blocking_issues": payload.get("blocking_issues", [])}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope CAI-style autonomous safe scanner")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["deps", "cai", "agentic"], default="agentic")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-params", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--request-budget", type=int, default=500)
    parser.add_argument("--max-actions", type=int, default=160)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--tool-timeout", type=int, default=20)
    parser.add_argument("--skip-100-tools", action="store_true")
    parser.add_argument("--skip-react", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", choices=["low", "normal", "high", "critical"], default="normal")
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--skip-tool-setup", action="store_true")
    parser.add_argument("--skip-ollama", action="store_true")
    parser.add_argument("--allow-ollama-fallback", action="store_true")
    parser.add_argument("--no-model-pull", action="store_true")
    parser.add_argument("--no-python-install", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true", default=True)
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-final-dashboard", action="store_true")
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", DEFAULT_OLLAMA_URL))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(VERSION)
        return 0
    print(BANNER)
    history: list[dict] = []
    if not args.skip_preflight:
        preflight = run_preflight_step(args)
        history.append(preflight)
        if not preflight.get("ok"):
            print("\nPreflight blocked launch because required local dependencies are missing. Fix the blocking items above, then run again.")
            return 2
    if args.mode == "deps":
        return 0 if all(x.get("ok") for x in history) else 2
    target = normalize_target(args.target or input("\nTarget URL/domain: ").strip())
    confirm(target, args.yes, args.scan_mode)
    history.append(run_cai(target, args) if args.mode == "cai" else run_agentic(target, args))
    final_summary(target, history)
    return 0 if all(x.get("ok") for x in history) else 1


if __name__ == "__main__":
    raise SystemExit(main())
