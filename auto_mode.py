#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from arsenal.catalog import load_profiles, tools_for_profile
from arsenal.healthcheck import print_healthcheck, run_healthcheck
from arsenal.installer import ensure_profile_tools
from arsenal.runner import run_tool

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope Auto Mode - curated setup and guided assessment workflow")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--url", help="Authorized target URL")
    parser.add_argument("--profile", default="bug-bounty-safe")
    parser.add_argument("--auto-install", action="store_true", help="Install missing curated tools after approval")
    parser.add_argument("--with-tools", action="store_true", help="Use installed profile tools with safety gates")
    parser.add_argument("--full", action="store_true", help="Run complete guided workflow")
    parser.add_argument("--providers", default="")
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--healthcheck", action="store_true")
    parser.add_argument("--list-profiles", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Auto Mode {VERSION}")
        return 0
    if args.list_profiles:
        for name, data in load_profiles().items():
            print(f"{name}: {data.get('description')}")
        return 0
    if args.healthcheck:
        print_healthcheck(run_healthcheck(args.profile))
        return 0
    if not args.url:
        print("[!] Provide authorized target with --url")
        return 1

    if args.full:
        args.auto_install = True
        args.with_tools = True

    tools = tools_for_profile(args.profile)
    print("┌──────────────────────── VulnScope Auto Mode ────────────────────────┐")
    print("│ Curated setup, safe templates, approval gates, and AI post-analysis. │")
    print("└─────────────────────────────────────────────────────────────────────┘")
    print(f"Target  : {args.url}")
    print(f"Profile : {args.profile}")
    print("Tools   : " + ", ".join(tool.name for tool in tools))

    install_state = ensure_profile_tools(tools, auto_install=args.auto_install, yes=args.yes)
    health = run_healthcheck(args.profile)
    print_healthcheck(health)

    if not args.dry_run:
        run_core_scan(args)

    tool_results = []
    if args.with_tools:
        for tool in tools:
            installed = install_state.get(tool.name) or any(item.get("name") == tool.name and item.get("installed") for item in health.get("tools", []))
            if installed:
                tool_results.append(run_tool(tool, args.url, yes=args.yes, dry_run=args.dry_run))

    write_summary(args, tool_results)

    if args.full and not args.dry_run:
        run_post_analysis(args)

    print("\n[+] Auto Mode finished.")
    print("[+] Summary: reports/output/auto-mode-summary.json")
    return 0


def run_core_scan(args: argparse.Namespace) -> None:
    py = sys.executable or "python3"
    command = [py, "vulnscope.py", "--url", args.url, "--mode", "passive", "--max-pages", str(args.max_pages), "--timeout", str(args.timeout), "--delay", str(args.delay), "--retries", str(args.retries)]
    print("\n[+] Core scan")
    print("    " + " ".join(command))
    subprocess.call(command)


def run_post_analysis(args: argparse.Namespace) -> None:
    py = sys.executable or "python3"
    commands = []
    ai_command = [py, "ai_discovery_cli.py", "--input", "reports/output/evidence.json"]
    if args.providers:
        ai_command += ["--providers", args.providers]
    commands.append(ai_command)
    commands.append([py, "mythic_hunter_cli.py", "--input", "reports/output/evidence.json", "--depth", "DEEP_HUNTER_MODE"])
    commands.append([py, "mythic_uplift_cli.py", "--input", "reports/output/evidence.json"])
    if Path("export_reports.py").exists():
        commands.append([py, "export_reports.py"])
    for command in commands:
        print("\n[+] " + " ".join(command))
        subprocess.call(command)


def write_summary(args: argparse.Namespace, tool_results: list[dict]) -> None:
    out = Path("reports/output")
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "target": args.url,
        "profile": args.profile,
        "auto_install": args.auto_install,
        "with_tools": args.with_tools,
        "tool_results": tool_results,
        "reports": [
            "reports/output/target-report.md",
            "reports/output/evidence.json",
            "reports/output/ai-discovery/ai-discovery-report.md",
            "reports/output/mythic/mythic-report.md",
            "reports/output/uplift/uplift-report.md",
        ],
    }
    (out / "auto-mode-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
