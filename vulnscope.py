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

VERSION = "1.15.2-batch-tool-installer"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"

BANNER = f"""
{CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗
║                          VulnScope Ultimate v{VERSION:<24}║
║        Batch Tool Installer → Phase Router → Deep Discovery → Evidence       ║
╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}
"""


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


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


def effective_scan_mode(args: argparse.Namespace) -> str:
    if getattr(args, "lab_mode", False):
        return "lab"
    if getattr(args, "mode", "") == "bugbounty" and args.scan_mode == "passive":
        return "safe-active"
    return args.scan_mode


def preprocess_argv(argv: list[str]) -> list[str]:
    """Make `--add-tool -tools.txt` work with argparse.

    A value beginning with '-' normally looks like an option to argparse. For this
    project, a single-dash value after --add-tool means a batch file path.
    `-tools.txt` becomes `--add-tool-file tools.txt` before parsing.
    """
    rewritten: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--add-tool" and index + 1 < len(argv):
            nxt = argv[index + 1]
            if nxt.startswith("-") and not nxt.startswith("--"):
                rewritten.extend(["--add-tool-file", nxt[1:]])
                index += 2
                continue
        rewritten.append(item)
        index += 1
    return rewritten


def run(label: str, command: list[str], timeout: int = 3600) -> dict:
    print(f"\n{c('[' + label + ']', CYAN)}", flush=True)
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


def confirm(target: str, yes: bool, scan_mode: str, include_subdomains: bool = False) -> None:
    host = host_from_target(target)
    print(c("\n[Authorization] Confirmed for: " + target, GREEN))
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        print("\nRules:")
        print("- You own this target, are using a local/intentionally vulnerable lab, or have explicit written authorization.")
        print("- VulnScope runs evidence-first defensive checks only.")
        print("- Production data modification is not allowed.")
        answer = input("\nType YES to confirm authorization: ").strip()
        if answer != "YES":
            raise SystemExit("Authorization not confirmed.")
    if scan_mode in {"safe-active", "lab"} and not yes and os.getenv("VULNSCOPE_SAFE_ACTIVE_OK", "0") != "1":
        answer = input(f"\n{scan_mode} mode sends harmless canary/check values to safe GET parameters. Type CONTINUE to proceed: ").strip()
        if answer != "CONTINUE":
            raise SystemExit(f"{scan_mode} mode not confirmed.")
    scope_text = f"Scope locked to {host}" + (" and subdomains." if include_subdomains else ".")
    print(c(f"  ℹ️  {scope_text}", CYAN))
    print(c(f"  ℹ️  Mode: {scan_mode}. No destructive actions, credential attacks, OOB callbacks, or service disruption.", CYAN))
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host, "scan_mode": scan_mode, "include_subdomains": include_subdomains, "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def final_summary(target: str, history: list[dict]) -> None:
    host = host_from_target(target)
    reports = {
        "dynamic_tool_registry": "tools/registry.json",
        "dynamic_tool_phase_summary": f"reports/output/cai-superior/{host}/dynamic-tool-phase-summary.json",
        "batch_tool_install_log": "logs/tool_install.log",
        "batch_tool_install_summary": "logs/tool_install_summary.json",
        "phase_runner_summary": f"reports/output/cai-superior/{host}/phase-runner-summary.json",
        "owasp_coverage": f"reports/output/cai-superior/{host}/owasp-coverage-report.md",
        "final_findings_dashboard": f"reports/output/cai-superior/{host}/final-findings-dashboard.md",
        "autonomous_report": f"reports/output/cai-superior/{host}/autonomous-scan-report.md",
        "autonomous_state": f"reports/output/cai-superior/{host}/autonomous-scan-state.json",
        "parameter_inventory_v2": f"reports/output/cai-superior/{host}/parameter-inventory-v2.json",
        "tool_router_matrix": f"reports/output/cai-superior/{host}/tool-router-matrix.json",
        "authorization": str(AUTH),
    }
    payload = {"target": target, "history": history, "reports": reports, "generated_at": datetime.now(timezone.utc).isoformat(), "version": VERSION, "batch_tool_installer": True, "dynamic_tool_registry": True, "website_dashboard": False}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "final-summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Summary", "", f"Target: `{target}`", "", f"Version: `{VERSION}`", "Batch tool installer: `true`", "Dynamic tool registry: `true`", "", "## Steps"]
    for item in history:
        lines.append(f"- `{item.get('label')}` ok=`{item.get('ok')}` exit=`{item.get('exit_code', 'n/a')}`")
    lines += ["", "## Reports"]
    for name, path in reports.items():
        lines.append(f"- `{name}`: `{path}`")
    (OUT / "final-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(c("\n✅ Full report written to: reports/output/cai-superior/" + host + "/", GREEN))
    for path in reports.values():
        print("   • " + path)


def append_headers(cmd: list[str], headers: list[str]) -> None:
    for header in headers or []:
        if ":" in header:
            cmd.extend(["--header", header])


def run_agentic(target: str, args: argparse.Namespace) -> dict:
    mode = effective_scan_mode(args)
    os.environ["VULNSCOPE_OLLAMA_MODEL"] = args.ollama_model
    os.environ["VULNSCOPE_OLLAMA_URL"] = args.ollama_url
    os.environ["VULNSCOPE_LLM_DECISION_INTERVAL"] = str(args.llm_decision_interval)
    os.environ["VULNSCOPE_LLM_DECISION_TIMEOUT"] = str(args.llm_decision_timeout)
    os.environ["VULNSCOPE_SCAN_MODE"] = mode
    if args.no_llm_planner:
        os.environ["VULNSCOPE_DISABLE_LLM_PLANNER"] = "1"
    history: list[dict] = []
    engine_cmd = [sys.executable, "-m", "core.autonomous_scan_engine", "--target", target, "--scan-mode", mode, "--max-pages", str(args.max_pages), "--max-depth", str(args.max_depth), "--max-params", str(args.max_params), "--request-timeout", str(args.request_timeout), "--delay", str(args.delay), "--request-budget", str(args.request_budget), "--max-actions", str(args.max_actions), "--asset-doc-limit", str(args.asset_doc_limit), "--ollama-url", args.ollama_url, "--ollama-model", args.ollama_model]
    if args.include_subdomains:
        engine_cmd.append("--include-subdomains")
    if args.resume:
        engine_cmd.append("--resume")
    if args.browser:
        engine_cmd.append("--browser")
    if args.no_live_dashboard:
        engine_cmd.append("--no-live-dashboard")
    if args.no_deep_assets:
        engine_cmd.append("--no-deep-assets")
    if args.no_dynamic_tools:
        engine_cmd.append("--no-dynamic-tools")
    append_headers(engine_cmd, args.header)
    history.append(run(f"Safe CAI ReAct Autonomous Engine ({mode})", engine_cmd, timeout=3600))
    ok = all(item.get("ok") for item in history)
    return {"label": f"VulnScope 1.15.2 {mode}", "ok": ok, "exit_code": 0 if ok else 1, "steps": history}


def run_cai(target: str, args: argparse.Namespace) -> dict:
    cmd = [sys.executable, "cai_superior_cli.py", "--target", target, "--criticality", args.criticality]
    if args.include_subdomains:
        cmd.append("--include-subdomains")
    return run("CAI checkpoint pipeline", cmd, timeout=3600)


def run_preflight_step(args: argparse.Namespace) -> dict:
    payload = run_preflight(install_python=not args.no_python_install, run_tool_setup_flag=not args.skip_tool_setup, check_ollama_flag=not args.skip_ollama, require_ollama=False, auto_pull_model=not args.no_model_pull, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    print_preflight_status(payload)
    return {"label": "Preflight", "ok": bool(payload.get("ok")), "exit_code": 0 if payload.get("ok") else 2, "summary": payload.get("summary", {}), "blocking_issues": payload.get("blocking_issues", [])}


def handle_tool_registry(args: argparse.Namespace) -> int | None:
    from core.tool_import_wizard import PROMPT_TOKEN, run_import_wizard
    from core.tool_manager import ToolManager
    manager = ToolManager()
    if args.list_tools:
        print(json.dumps({"tools": manager.list_tools()}, indent=2, ensure_ascii=False))
        return 0
    if args.approve_tool:
        tool = manager.registry.approve(args.approve_tool, install=args.approve_tool_install, run=args.approve_tool_run, enable=args.enable_tool)
        print(json.dumps({"approved": tool.to_dict()}, indent=2, ensure_ascii=False))
        return 0
    if args.add_tool_file:
        summary = manager.install_from_file(args.add_tool_file, confirm_authorization=args.yes, install_timeout=args.tool_install_timeout)
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f"\n{summary.get('installed_successfully', 0)} tools installed successfully, {summary.get('failed', 0)} failed.")
        return 0 if summary.get("status") == "completed" else 2
    if args.add_tool is not None:
        return run_import_wizard(args.add_tool if args.add_tool else PROMPT_TOKEN, yes=args.yes)
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope CAI-style autonomous safe scanner")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["deps", "cai", "agentic", "bugbounty"], default="agentic")
    parser.add_argument("--lab-mode", action="store_true")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--add-tool", nargs="?", const="__prompt__", default=None, help="Simple tool import. Use --add-tool -tools.txt for batch file import.")
    parser.add_argument("--add-tool-file", default="", help="Batch install GitHub tool URLs from a file. Usually produced by --add-tool -tools.txt.")
    parser.add_argument("--list-tools", action="store_true", help="List dynamic tools registered in tools/registry.json.")
    parser.add_argument("--approve-tool", default="", help="Approve an existing dynamic tool by id.")
    parser.add_argument("--approve-tool-install", action="store_true")
    parser.add_argument("--approve-tool-run", action="store_true")
    parser.add_argument("--enable-tool", action="store_true")
    parser.add_argument("--tool-install-timeout", type=int, default=900)
    parser.add_argument("--no-dynamic-tools", action="store_true")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-params", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--request-budget", type=int, default=500)
    parser.add_argument("--max-actions", type=int, default=160)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--asset-doc-limit", type=int, default=40)
    parser.add_argument("--no-deep-assets", action="store_true")
    parser.add_argument("--llm-decision-interval", type=int, default=4)
    parser.add_argument("--llm-decision-timeout", type=int, default=6)
    parser.add_argument("--no-llm-planner", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--tool-timeout", type=int, default=20)
    parser.add_argument("--with-100-tools", action="store_true")
    parser.add_argument("--with-legacy-react", action="store_true")
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
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args(preprocess_argv(sys.argv[1:]))
    if args.version:
        print(VERSION)
        return 0
    registry_result = handle_tool_registry(args)
    if registry_result is not None:
        return registry_result
    print(BANNER)
    history: list[dict] = []
    if not args.skip_preflight:
        preflight = run_preflight_step(args)
        history.append(preflight)
        if not preflight.get("ok"):
            print(c("\nPreflight blocked launch because required local dependencies are missing. Fix the blocking items above, then run again.", RED))
            return 2
    if args.mode == "deps":
        return 0 if all(x.get("ok") for x in history) else 2
    target = normalize_target(args.target or input("\nTarget URL/domain: ").strip())
    mode = effective_scan_mode(args)
    confirm(target, args.yes, mode, include_subdomains=args.include_subdomains)
    print(c(f"\n🚀 Starting phase-stable autonomous scan in {mode} mode... (Ctrl+C to stop)", GREEN))
    history.append(run_cai(target, args) if args.mode == "cai" else run_agentic(target, args))
    final_summary(target, history)
    return 0 if all(x.get("ok") for x in history) else 1


if __name__ == "__main__":
    raise SystemExit(main())
