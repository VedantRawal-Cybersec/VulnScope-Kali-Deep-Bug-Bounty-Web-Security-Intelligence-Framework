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

VERSION = "2.0.1-deepseek-dashboard"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"

BANNER = f"""
{CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗
║                          VulnScope Ultimate v{VERSION:<24}║
║          DeepSeek AI → Live Dashboard → Deep Discovery → Final Report         ║
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
    if getattr(args, "lab_mode", False) or getattr(args, "mode", "") == "lab":
        return "lab"
    if getattr(args, "mode", "") in {"bugbounty", "react"} and args.scan_mode == "passive":
        return "safe-active"
    return args.scan_mode


def confirm(target: str, yes: bool, scan_mode: str, include_subdomains: bool = False) -> None:
    host = host_from_target(target)
    print(c("\n[Authorization] Target: " + target, GREEN))
    if scan_mode == "lab":
        print(c("Lab mode is intended only for owned labs, training systems, or deliberately vulnerable targets.", YELLOW))
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        print("\nRules:")
        print("- You own this target or have explicit written authorization.")
        print("- VulnScope keeps execution approval-gated and writes evidence-first reports.")
        answer = input("\nDo you have explicit written authorization to test this target? (yes/no): ").strip().lower()
        if answer not in {"yes", "y"}:
            raise SystemExit("Authorization not confirmed.")
    scope_text = f"Scope locked to {host}" + (" and subdomains." if include_subdomains else ".")
    print(c(f"  ℹ️  {scope_text}", CYAN))
    print(c(f"  ℹ️  Mode: {scan_mode}.", CYAN))
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host, "scan_mode": scan_mode, "include_subdomains": include_subdomains, "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def run(label: str, command: list[str], timeout: int = 3600, env: dict[str, str] | None = None) -> dict:
    print(f"\n{c('[' + label + ']', CYAN)}", flush=True)
    print("$ " + " ".join(command), flush=True)
    started = datetime.now(timezone.utc)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    merged_env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, env=merged_env)
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


def deep_defaults(args: argparse.Namespace) -> dict[str, int | float]:
    return {
        "max_pages": max(int(args.max_pages), 350),
        "max_depth": max(int(args.max_depth), 5),
        "max_params": max(int(args.max_params), 600),
        "request_timeout": max(int(args.request_timeout), 12),
        "delay": min(float(args.delay), 0.25),
        "request_budget": max(int(args.request_budget), 2500),
        "max_actions": max(int(args.max_actions), 320),
        "asset_doc_limit": max(int(args.asset_doc_limit), 80),
    }


def engine_command(target: str, args: argparse.Namespace, *, scan_mode: str, deep: bool = False) -> list[str]:
    opts = deep_defaults(args) if deep else {
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "max_params": args.max_params,
        "request_timeout": args.request_timeout,
        "delay": args.delay,
        "request_budget": args.request_budget,
        "max_actions": args.max_actions,
        "asset_doc_limit": args.asset_doc_limit,
    }
    cmd = [
        sys.executable,
        "-m",
        "core.autonomous_scan_engine",
        "--target",
        target,
        "--scan-mode",
        scan_mode,
        "--max-pages",
        str(opts["max_pages"]),
        "--max-depth",
        str(opts["max_depth"]),
        "--max-params",
        str(opts["max_params"]),
        "--request-timeout",
        str(opts["request_timeout"]),
        "--delay",
        str(opts["delay"]),
        "--request-budget",
        str(opts["request_budget"]),
        "--max-actions",
        str(opts["max_actions"]),
        "--asset-doc-limit",
        str(opts["asset_doc_limit"]),
        "--ollama-url",
        args.ollama_url,
        "--ollama-model",
        args.ollama_model,
    ]
    if args.include_subdomains:
        cmd.append("--include-subdomains")
    if args.resume:
        cmd.append("--resume")
    if args.browser or deep:
        cmd.append("--browser")
    if args.no_live_dashboard:
        cmd.append("--no-live-dashboard")
    if args.no_deep_assets:
        cmd.append("--no-deep-assets")
    if args.no_dynamic_tools:
        cmd.append("--no-dynamic-tools")
    for header in args.header or []:
        if ":" in header:
            cmd.extend(["--header", header])
    return cmd


def run_agentic(target: str, args: argparse.Namespace) -> dict:
    mode = effective_scan_mode(args)
    env = {"OLLAMA_HOST": args.ollama_url, "VULNSCOPE_OLLAMA_MODEL": args.ollama_model, "VULNSCOPE_OLLAMA_URL": args.ollama_url, "VULNSCOPE_SCAN_MODE": mode}
    return run(f"Phase-stable autonomous engine ({mode})", engine_command(target, args, scan_mode=mode), timeout=3600, env=env)


def auto_discover_tools(target: str, brain, *, approve_install: bool = False, approve_run: bool = False) -> list[dict]:
    from core.ai_tool_discovery import AIToolDiscovery
    from core.dynamic_tool_installer import DynamicToolInstaller
    context = {"target": target, "host": host_from_target(target), "goal": "discover defensive web assessment tools"}
    discovery = AIToolDiscovery(brain)
    installer = DynamicToolInstaller(brain)
    repos = discovery.discover(context, per_query=2, max_total=8)
    results: list[dict] = []
    for repo_url in repos:
        try:
            results.append(installer.install_and_register(repo_url, approve_install=approve_install, approve_run=approve_run, enable=True))
        except Exception as exc:
            results.append({"repo_url": repo_url, "ok": False, "error": str(exc)})
    out = Path("logs/auto_discover_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return results


def load_engine_findings(target: str) -> tuple[list[dict], dict]:
    host = host_from_target(target)
    state_path = Path("reports/output/cai-superior") / host / "autonomous-scan-state.json"
    if not state_path.exists():
        return [], {"state_path": str(state_path), "state_found": False}
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [], {"state_path": str(state_path), "state_found": True, "error": str(exc)}
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    return findings, {"state_path": str(state_path), "state_found": True, "coverage": payload.get("stats", {}), "urls": len(payload.get("urls", {})), "params": len(payload.get("params", {}))}


def write_deepseek_report(target: str, args: argparse.Namespace, engine_result: dict) -> dict:
    from core.ai_brain import AIBrain
    from core.report_generator import ReportGenerator
    brain = AIBrain(model=args.ollama_model or "deepseek-local")
    findings, context = load_engine_findings(target)
    context["engine_result"] = engine_result
    out_dir = Path(args.out_dir) if args.out_dir else Path("reports/output") / host_from_target(target)
    report_path = ReportGenerator(brain).write_report(target, findings, out_dir=out_dir, context=context)
    react_final = out_dir / "vulnscope-react-final.json"
    payload = {"target": target, "findings": findings, "report_path": str(report_path), "engine_result": engine_result, "context": context, "generated_at": datetime.now(timezone.utc).isoformat()}
    react_final.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"report_path": str(report_path), "react_final": str(react_final), "findings": len(findings), "context": context}


def run_react_ai(target: str, args: argparse.Namespace) -> dict:
    from core.ai_brain import AIBrain
    mode = "lab" if args.mode == "lab" or args.lab_mode else "safe-active"
    if args.aggressive and mode != "lab":
        print(c("Aggressive mode is lab-only. Running safe-active DeepSeek dashboard mode.", YELLOW))
    brain = AIBrain(model=args.ollama_model or "deepseek-local")
    print(c(f"\n[DeepSeek] Host: {brain.ollama_host} | Model: {brain.model}", CYAN))
    if args.auto_discover:
        print(c("\n[Auto-Discover] Searching and registering candidate tools...", CYAN))
        results = auto_discover_tools(target, brain, approve_install=args.approve_install, approve_run=args.approve_run and mode == "lab")
        print(json.dumps({"auto_discover_results": len(results), "log": "logs/auto_discover_results.json"}, indent=2))
    env = {"OLLAMA_HOST": args.ollama_url, "VULNSCOPE_OLLAMA_MODEL": args.ollama_model, "VULNSCOPE_OLLAMA_URL": args.ollama_url, "VULNSCOPE_SCAN_MODE": mode, "VULNSCOPE_REACT_AI": "1"}
    print(c("\n[DeepSeek Dashboard] Launching full crawler + JS + parameter + dynamic-tool engine...", GREEN))
    engine_result = run("DeepSeek dashboard autonomous engine", engine_command(target, args, scan_mode=mode, deep=True), timeout=7200, env=env)
    report_info = write_deepseek_report(target, args, engine_result)
    submission = {"submitted": False, "reason": "submit flag not set"}
    if args.submit:
        from core.bounty_integrator import BountyIntegrator
        if not args.program:
            submission = {"submitted": False, "reason": "missing --program"}
        else:
            answer = input("Submit final report to the selected platform? Type SUBMIT to continue: ").strip()
            if answer == "SUBMIT":
                integrator = BountyIntegrator(args.platform, api_key=args.api_key)
                findings, _context = load_engine_findings(target)
                submission = integrator.submit_report(program=args.program, report_path=report_info.get("report_path", ""), target=target, findings=findings, confirm=True)
            else:
                submission = {"submitted": False, "reason": "user cancelled"}
    ok = bool(engine_result.get("ok"))
    return {"label": "DeepSeek dashboard AI", "ok": ok, "exit_code": 0 if ok else 1, "engine": engine_result, "report": report_info, "submission": submission}


def handle_tool_registry(args: argparse.Namespace) -> int | None:
    from core.tool_manager import ToolManager
    manager = ToolManager()
    if args.ai_repair_tools:
        from core.ai_tool_registry_repair import AIToolRegistryRepair
        payload = AIToolRegistryRepair(timeout=args.ai_tool_probe_timeout, use_llm=not args.no_ai_tool_llm).repair_all(approve_safe_run=args.ai_repair_approve_safe_run, enable=not args.ai_tool_disable, limit=args.ai_repair_limit)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    if args.ai_add_tool:
        from core.ai_tool_auto_configurator import AIToolAutoConfigurator
        payload = AIToolAutoConfigurator(timeout=args.ai_tool_probe_timeout, use_llm=not args.no_ai_tool_llm).configure(args.ai_add_tool, install=args.ai_tool_install, approve_install=args.ai_tool_install, approve_run=args.ai_tool_approve_run, enable=not args.ai_tool_disable)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if payload.get("status") in {"READY", "REGISTERED_REQUIRES_APPROVAL", "NEEDS_MANUAL_REVIEW"} else 2
    if args.ai_add_tool_file:
        from core.ai_tool_auto_configurator import AIToolAutoConfigurator
        payload = AIToolAutoConfigurator(timeout=args.ai_tool_probe_timeout, use_llm=not args.no_ai_tool_llm).configure_file(args.ai_add_tool_file, install=args.ai_tool_install, approve_install=args.ai_tool_install, approve_run=args.ai_tool_approve_run, enable=not args.ai_tool_disable)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    if args.list_tools:
        print(json.dumps({"tools": manager.list_tools()}, indent=2, ensure_ascii=False))
        return 0
    if args.approve_tool:
        tool = manager.registry.approve(args.approve_tool, install=args.approve_tool_install, run=args.approve_tool_run, enable=args.enable_tool)
        print(json.dumps({"approved": tool.to_dict()}, indent=2, ensure_ascii=False))
        return 0
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope DeepSeek dashboard autonomous security assessment framework")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["agentic", "bugbounty", "lab", "react"], default="agentic")
    parser.add_argument("--react-ai", action="store_true", help="Run DeepSeek through the full live dashboard engine.")
    parser.add_argument("--aggressive", action="store_true", help="Lab-only higher-intensity approved tool profile.")
    parser.add_argument("--auto-discover", action="store_true")
    parser.add_argument("--approve-install", action="store_true")
    parser.add_argument("--approve-run", action="store_true")
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--platform", choices=["hackerone", "bugcrowd"], default="hackerone")
    parser.add_argument("--program", default="")
    parser.add_argument("--api-key", default=os.getenv("BOUNTY_API_KEY", ""))
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--lab-mode", action="store_true")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--ai-add-tool", default="")
    parser.add_argument("--ai-add-tool-file", default="")
    parser.add_argument("--ai-repair-tools", action="store_true")
    parser.add_argument("--ai-repair-approve-safe-run", action="store_true")
    parser.add_argument("--ai-repair-limit", type=int, default=0)
    parser.add_argument("--ai-tool-install", action="store_true")
    parser.add_argument("--ai-tool-approve-run", action="store_true")
    parser.add_argument("--ai-tool-disable", action="store_true")
    parser.add_argument("--ai-tool-probe-timeout", type=int, default=25)
    parser.add_argument("--no-ai-tool-llm", action="store_true")
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--approve-tool", default="")
    parser.add_argument("--approve-tool-install", action="store_true")
    parser.add_argument("--approve-tool-run", action="store_true")
    parser.add_argument("--enable-tool", action="store_true")
    parser.add_argument("--no-dynamic-tools", action="store_true")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-params", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--request-budget", type=int, default=500)
    parser.add_argument("--max-actions", type=int, default=160)
    parser.add_argument("--asset-doc-limit", type=int, default=40)
    parser.add_argument("--no-deep-assets", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true", default=True)
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--ollama-url", default=os.getenv("OLLAMA_HOST", "http://192.168.199.1:11434"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "deepseek-local"))
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        os.environ["VULNSCOPE_IGNORED_ARGS"] = " ".join(unknown)
    return args


def final_summary(target: str, history: list[dict]) -> None:
    host = host_from_target(target)
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {"target": target, "history": history, "generated_at": datetime.now(timezone.utc).isoformat(), "version": VERSION}
    (OUT / "final-summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(c("\n✅ VulnScope run complete.", GREEN))
    print("   • reports/output/cai-superior/" + host + "/")
    print("   • reports/output/" + host + "/final-report.md")
    print("   • reports/output/" + host + "/vulnscope-react-final.json")
    print("   • reports/output/vulnscope-main/final-summary.json")


def main() -> int:
    args = parse_args(sys.argv[1:])
    if args.version:
        print(VERSION)
        return 0
    registry_result = handle_tool_registry(args)
    if registry_result is not None:
        return registry_result
    print(BANNER)
    target = normalize_target(args.target or input("\nTarget URL/domain: ").strip())
    mode = "lab" if args.mode == "lab" or args.lab_mode else effective_scan_mode(args)
    confirm(target, args.yes, mode, include_subdomains=args.include_subdomains)
    if args.react_ai or args.mode == "react" or args.auto_discover or args.aggressive or args.submit:
        result = run_react_ai(target, args)
    else:
        result = run_agentic(target, args)
    history = [result]
    final_summary(target, history)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
