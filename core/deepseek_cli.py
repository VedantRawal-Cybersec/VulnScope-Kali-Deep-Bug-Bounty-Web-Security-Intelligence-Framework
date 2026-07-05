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

VERSION = "2.0.2-autonomous-deepseek"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


def normalize_target(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise SystemExit("target is required")
    return value if "://" in value else "https://" + value


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = (parsed.hostname or parsed.netloc or "").split(":")[0].lower().strip()
    if not host:
        raise SystemExit("invalid target")
    return host


def selected_mode(args: argparse.Namespace) -> str:
    if args.mode == "lab" or args.lab_mode:
        return "lab"
    if args.mode in {"bugbounty", "react"}:
        return "safe-active"
    return args.scan_mode


def confirm(target: str, mode: str, yes: bool, include_subdomains: bool) -> None:
    host = host_from_target(target)
    print(c("\n[Authorization] Target: " + target, GREEN))
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        print("\nRules:")
        print("- Use only on systems you own or have permission to assess.")
        print("- The run remains scoped and report-driven.")
        answer = input("\nDo you have authorization? (yes/no): ").strip().lower()
        if answer not in {"yes", "y"}:
            raise SystemExit("Authorization not confirmed.")
    print(c("  Scope: " + host + (" + subdomains" if include_subdomains else ""), CYAN))
    print(c("  Mode: " + mode, CYAN))
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host, "mode": mode, "include_subdomains": include_subdomains, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def deep_values(args: argparse.Namespace, deep: bool) -> dict[str, int | float]:
    if not deep:
        return {"max_pages": args.max_pages, "max_depth": args.max_depth, "max_params": args.max_params, "request_timeout": args.request_timeout, "delay": args.delay, "request_budget": args.request_budget, "max_actions": args.max_actions, "asset_doc_limit": args.asset_doc_limit}
    return {"max_pages": max(args.max_pages, 350), "max_depth": max(args.max_depth, 5), "max_params": max(args.max_params, 600), "request_timeout": max(args.request_timeout, 12), "delay": min(args.delay, 0.25), "request_budget": max(args.request_budget, 2500), "max_actions": max(args.max_actions, 320), "asset_doc_limit": max(args.asset_doc_limit, 80)}


def build_command(target: str, args: argparse.Namespace, mode: str, module: str, deep: bool) -> list[str]:
    values = deep_values(args, deep)
    cmd = [sys.executable, "-m", module, "--target", target, "--scan-mode", mode, "--max-pages", str(values["max_pages"]), "--max-depth", str(values["max_depth"]), "--max-params", str(values["max_params"]), "--request-timeout", str(values["request_timeout"]), "--delay", str(values["delay"]), "--request-budget", str(values["request_budget"]), "--max-actions", str(values["max_actions"]), "--asset-doc-limit", str(values["asset_doc_limit"]), "--ollama-url", args.ollama_url, "--ollama-model", args.ollama_model]
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


def run_subprocess(label: str, command: list[str], env: dict[str, str], timeout: int = 7200) -> dict:
    print(c("\n[" + label + "]", CYAN), flush=True)
    print("$ " + " ".join(command), flush=True)
    merged_env = os.environ.copy()
    merged_env.update(env)
    merged_env["PYTHONUNBUFFERED"] = "1"
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.Popen(command, env=merged_env)
        exit_code = proc.wait(timeout=timeout)
        return {"label": label, "ok": exit_code == 0, "exit_code": exit_code, "command": command, "started_at": started.isoformat(), "ended_at": datetime.now(timezone.utc).isoformat()}
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"label": label, "ok": False, "error": "timeout", "command": command, "started_at": started.isoformat()}
    except Exception as exc:
        return {"label": label, "ok": False, "error": str(exc), "command": command, "started_at": started.isoformat()}


def handle_tools(args: argparse.Namespace) -> int | None:
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
    parser = argparse.ArgumentParser(description="VulnScope DeepSeek runner")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["agentic", "bugbounty", "lab", "react"], default="agentic")
    parser.add_argument("--react-ai", action="store_true")
    parser.add_argument("--lab-mode", action="store_true")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-deep-assets", action="store_true")
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
    parser.add_argument("--ollama-url", default=os.getenv("OLLAMA_HOST", "http://192.168.199.1:11434"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "deepseek-local"))
    parser.add_argument("--ai-repair-tools", action="store_true")
    parser.add_argument("--ai-repair-approve-safe-run", action="store_true")
    parser.add_argument("--ai-repair-limit", type=int, default=0)
    parser.add_argument("--ai-add-tool", default="")
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
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        os.environ["VULNSCOPE_IGNORED_ARGS"] = " ".join(unknown)
    return args


def finish(target: str, result: dict) -> None:
    host = host_from_target(target)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "final-summary.json").write_text(json.dumps({"target": target, "result": result, "version": VERSION, "generated_at": datetime.now(timezone.utc).isoformat()}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(c("\n✅ VulnScope run complete.", GREEN))
    print("   • reports/output/cai-superior/" + host + "/")
    print("   • reports/output/vulnscope-main/final-summary.json")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.version:
        print(VERSION)
        return 0
    handled = handle_tools(args)
    if handled is not None:
        return handled
    print(c(f"\nVulnScope Ultimate v{VERSION}", CYAN))
    target = normalize_target(args.target or input("\nTarget URL/domain: ").strip())
    mode = selected_mode(args)
    confirm(target, mode, args.yes, args.include_subdomains)
    react = args.react_ai or args.mode == "react"
    module = "core.deepseek_dashboard_engine" if react else "core.autonomous_scan_engine"
    env = {"OLLAMA_HOST": args.ollama_url, "VULNSCOPE_OLLAMA_URL": args.ollama_url, "VULNSCOPE_OLLAMA_MODEL": args.ollama_model, "VULNSCOPE_SCAN_MODE": mode, "VULNSCOPE_REACT_AI": "1" if react else "0"}
    if react:
        print(c(f"\n[DeepSeek] Host: {args.ollama_url} | Model: {args.ollama_model}", CYAN))
        print(c("[DeepSeek] Starting dashboard autonomy loop.", GREEN))
    result = run_subprocess("DeepSeek dashboard engine" if react else "dashboard engine", build_command(target, args, mode, module, react), env)
    finish(target, result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
