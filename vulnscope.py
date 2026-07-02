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

VERSION = "1.6.2-hard-timeout-100-tool-orchestrator"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                         VulnScope Ultimate                       ║
║  Preflight → Consent → 100 Tools with Timeout → Live ReAct → Report ║
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


def confirm(target: str, yes: bool) -> None:
    print("\nAuthorized use only. Scope is locked to the target you provide.")
    print(f"Target: {target}")
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        print("\nRules:")
        print("- You own this target or have explicit written authorization.")
        print("- VulnScope runs evidence-first defensive checks only.")
        print("- Production data modification and credential attacks are not allowed.")
        answer = input("\nType YES to confirm authorization: ").strip()
        if answer != "YES":
            raise SystemExit("Authorization not confirmed.")
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host_from_target(target), "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def final_summary(target: str, history: list[dict]) -> None:
    host = host_from_target(target)
    reports = {
        "preflight": "reports/output/vulnscope-main/preflight.md",
        "tool_matrix": f"reports/output/cai-superior/{host}/tool-matrix.md",
        "tool_matrix_json": f"reports/output/cai-superior/{host}/tool-matrix.json",
        "tool_registry_100": f"reports/output/cai-superior/{host}/tool-registry-100.json",
        "cli_final_dashboard": f"reports/output/cai-superior/{host}/cli-final-dashboard.md",
        "cli_session": f"reports/output/cai-superior/{host}/cli-session.json",
        "detailed_findings": f"reports/output/cai-superior/{host}/detailed-findings.json",
        "react_loop": f"reports/output/cai-superior/{host}/react-run.md",
        "react_state": f"reports/output/cai-superior/{host}/react-state.md",
        "authorization": str(AUTH),
    }
    payload = {"target": target, "history": history, "reports": reports, "generated_at": datetime.now(timezone.utc).isoformat(), "interface": "kali_cli", "dashboard": "visible_100_tool_cli_direct_output", "hundred_tool_orchestrator": True, "hard_timeout_per_actuator": True, "live_output_default": True, "final_dashboard_direct_stdout": True, "website_dashboard": False}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "final-summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Summary", "", f"Target: `{target}`", "", "Interface: `Kali CLI live dashboard`", "100-tool orchestrator: `true`", "Hard timeout per actuator: `true`", "Live output default: `true`", "Direct stdout dashboard: `true`", "Website dashboard: `false`", "", "## Steps"]
    for item in history:
        lines.append(f"- `{item.get('label')}` ok=`{item.get('ok')}` exit=`{item.get('exit_code', 'n/a')}`")
    lines += ["", "## Reports"]
    for name, path in reports.items():
        lines.append(f"- `{name}`: `{path}`")
    (OUT / "final-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\nOpen reports:")
    for path in reports.values():
        print("- " + path)


def run_agentic(target: str, args: argparse.Namespace) -> dict:
    os.environ["VULNSCOPE_OLLAMA_MODEL"] = args.ollama_model
    os.environ["VULNSCOPE_OLLAMA_URL"] = args.ollama_url
    history: list[dict] = []
    orch_cmd = [sys.executable, "-m", "core.tool_orchestrator", "--target", target, "--scan-mode", args.scan_mode, "--criticality", args.criticality, "--tool-timeout", str(args.tool_timeout)]
    if args.include_subdomains:
        orch_cmd.append("--include-subdomains")
    if args.no_live_dashboard:
        orch_cmd.append("--no-live-dashboard")
    history.append(run("Live 100-Tool Safe Orchestrator", orch_cmd, timeout=3600))

    cmd = [sys.executable, "-m", "core.react_loop", "--target", target, "--max-turns", str(args.max_turns), "--criticality", args.criticality]
    if args.include_subdomains:
        cmd.append("--include-subdomains")
    if args.force:
        cmd.append("--force")
    if not args.no_live_dashboard:
        cmd.append("--live-dashboard")
    if args.no_final_dashboard:
        cmd.append("--no-final-dashboard")
    history.append(run("Live Autonomous Ollama/ReAct Loop", cmd, timeout=3600))
    ok = all(item.get("ok") for item in history)
    return {"label": "Visible Ultimate Agentic Pipeline", "ok": ok, "exit_code": 0 if ok else 1, "steps": history}


def run_cai(target: str, args: argparse.Namespace) -> dict:
    cmd = [sys.executable, "cai_superior_cli.py", "--target", target, "--criticality", args.criticality]
    if args.include_subdomains:
        cmd.append("--include-subdomains")
    return run("CAI checkpoint pipeline", cmd, timeout=3600)


def run_preflight_step(args: argparse.Namespace) -> dict:
    payload = run_preflight(
        install_python=not args.no_python_install,
        run_tool_setup_flag=not args.skip_tool_setup,
        check_ollama_flag=not args.skip_ollama,
        require_ollama=False,
        auto_pull_model=not args.no_model_pull,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
    )
    print_preflight_status(payload)
    return {"label": "Preflight", "ok": bool(payload.get("ok")), "exit_code": 0 if payload.get("ok") else 2, "summary": payload.get("summary", {}), "blocking_issues": payload.get("blocking_issues", [])}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope one-command safe autonomous launcher")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["deps", "cai", "agentic"], default="agentic")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--tool-timeout", type=int, default=20, help="Hard timeout in seconds for each unique 100-tool actuator call.")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", choices=["low", "normal", "high", "critical"], default="normal")
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--skip-tool-setup", action="store_true")
    parser.add_argument("--skip-ollama", action="store_true")
    parser.add_argument("--allow-ollama-fallback", action="store_true", help="Compatibility flag. Fallback is allowed by default when Ollama is unavailable.")
    parser.add_argument("--no-model-pull", action="store_true")
    parser.add_argument("--no-python-install", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true", default=True, help="Compatibility flag. Live dashboard is enabled by default.")
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
    confirm(target, args.yes)
    history.append(run_cai(target, args) if args.mode == "cai" else run_agentic(target, args))
    final_summary(target, history)
    return 0 if all(x.get("ok") for x in history) else 1


if __name__ == "__main__":
    raise SystemExit(main())
