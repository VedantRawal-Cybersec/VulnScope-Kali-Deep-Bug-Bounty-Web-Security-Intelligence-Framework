#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from cli_ui.banner import print_banner
from cli_ui.components import artifact_table, command_hint, error, info, json_panel, panel, provider_table, success, warn
from cli_ui.menus import show_command_for_choice, show_menu
from cli_ui.theme import get_console
from agent_core.providers.provider_manager import provider_report

VERSION = "1.0.0-pro"

ARTIFACTS = [
    "reports/output/autonomy/autonomy-run.json",
    "reports/output/autonomy/autonomy-plan.md",
    "reports/output/agent_core/agent-core-summary.json",
    "reports/output/agent_core/model-council/council-consensus.md",
    "reports/output/evidence-graph/evidence-graph.json",
    "reports/output/validation/replay-validation.json",
    "reports/output/finding-quality.json",
    "reports/output/report-v2/executive-report-v2.md",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope Pro premium command center")
    parser.add_argument("command", nargs="?", choices=["menu", "status", "providers", "artifacts", "doctor", "quickstart", "run"], default="menu")
    parser.add_argument("--target")
    parser.add_argument("--mode", default="comprehensive")
    parser.add_argument("--provider", default="anthropic")
    parser.add_argument("--har-import")
    parser.add_argument("--execute", action="store_true", help="Execute generated command instead of only showing it")
    parser.add_argument("--no-banner", action="store_true")
    return parser.parse_args()


def run_shell(command: str) -> int:
    command_hint(command)
    return subprocess.call(command, shell=True)


def doctor() -> int:
    checks = {
        "scope_policy.yaml": Path("scope_policy.yaml").exists(),
        "autonomy_policy.yaml": Path("autonomy_policy.yaml").exists(),
        ".env.local": Path(".env.local").exists(),
        "reports/output": Path("reports/output").exists(),
    }
    json_panel("System Checks", checks)
    provider_table(provider_report())
    missing = [k for k, v in checks.items() if not v]
    if missing:
        warn("Some files are missing. Run quickstart to initialize them.")
        command_hint("python3 vulnscope_pro.py quickstart --execute")
    else:
        success("Environment looks ready.")
    return 0


def quickstart(execute: bool = False) -> int:
    commands = [
        "python3 hunt.py --init-scope-policy",
        "python3 autopilot_cli.py --init-policy",
        "python3 ai_provider_cli.py --status",
        "python3 dashboard_cli.py --once",
    ]
    panel("Quickstart", "Initialize policies, verify AI providers, and check dashboard readiness.")
    rc = 0
    for cmd in commands:
        command_hint(cmd)
        if execute:
            rc = subprocess.call(cmd, shell=True)
            if rc != 0:
                return rc
    return rc


def run_autopilot(args: argparse.Namespace) -> int:
    if not args.target:
        error("Provide --target for run command.")
        return 1
    cmd = f"python3 autopilot_cli.py --target {args.target} --mode {args.mode} --provider {args.provider} --yes"
    if args.har_import:
        cmd += f" --har-import {args.har_import}"
    if args.execute:
        return run_shell(cmd)
    command_hint(cmd)
    return 0


def interactive_menu(execute: bool = False) -> int:
    while True:
        choice = show_menu()
        cmd = show_command_for_choice(choice)
        if not cmd:
            return 0
        if execute:
            run_shell(cmd)
            get_console().print("\n[vs.muted]Press Enter to continue...[/vs.muted]")
            try:
                input()
            except KeyboardInterrupt:
                return 130
        else:
            info("Use --execute to run commands directly from the launcher.")
            return 0


def main() -> int:
    args = parse_args()
    if not args.no_banner:
        print_banner(VERSION, args.command)
    if args.command == "menu":
        return interactive_menu(args.execute)
    if args.command == "providers":
        provider_table(provider_report())
        return 0
    if args.command == "artifacts":
        artifact_table(ARTIFACTS)
        return 0
    if args.command == "doctor" or args.command == "status":
        return doctor()
    if args.command == "quickstart":
        return quickstart(args.execute)
    if args.command == "run":
        return run_autopilot(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
