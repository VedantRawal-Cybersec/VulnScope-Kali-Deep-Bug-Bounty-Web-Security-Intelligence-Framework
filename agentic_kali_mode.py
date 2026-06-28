#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

VERSION = "0.1.0"


@dataclass
class Step:
    name: str
    command: list[str]
    required: bool = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope Agentic Kali Mode - safe authorized workflow orchestrator")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--url", required=False, help="Authorized target URL")
    parser.add_argument("--mode", default="passive", choices=["passive", "safe-active"])
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--providers", default="", help="AI providers: openai,gemini,groq,openrouter")
    parser.add_argument("--with-ai", action="store_true", help="Run AI discovery after scanner evidence is produced")
    parser.add_argument("--with-mythic", action="store_true", help="Run Mythic Hunter validation")
    parser.add_argument("--with-uplift", action="store_true", help="Run advanced uplift analyzer")
    parser.add_argument("--export", action="store_true", help="Export reports to a ZIP if export_reports.py is present")
    parser.add_argument("--full", action="store_true", help="Run scan + AI discovery + Mythic + Uplift + export")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without running them")
    parser.add_argument("--yes", action="store_true", help="Skip interactive confirmation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Agentic Kali Mode {VERSION}")
        return 0
    if not args.url:
        print("[!] Provide an authorized target with --url")
        return 1

    if args.full:
        args.with_ai = True
        args.with_mythic = True
        args.with_uplift = True
        args.export = True

    steps = build_steps(args)
    print_banner(args, steps)

    if args.dry_run:
        return 0

    if not args.yes:
        answer = input("\nDo you confirm this target is authorized and in scope? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print("[!] Cancelled. Authorization is required.")
            return 1

    failures = []
    for step in steps:
        print(f"\n[+] Running: {step.name}")
        print("    " + " ".join(step.command))
        code = subprocess.call(step.command)
        if code != 0:
            failures.append({"step": step.name, "code": code})
            print(f"[!] Step failed: {step.name} exit={code}")
            if step.required:
                print("[!] Required step failed. Stopping workflow.")
                return code

    if failures:
        print("\n[!] Workflow finished with optional step failures:")
        for failure in failures:
            print(f"- {failure['step']}: exit {failure['code']}")
        return 1

    print("\n[+] Agentic Kali Mode workflow completed successfully.")
    return 0


def build_steps(args: argparse.Namespace) -> list[Step]:
    py = sys.executable or "python3"
    steps = [
        Step(
            "VulnScope scanner",
            [
                py,
                "vulnscope.py",
                "--url",
                args.url,
                "--mode",
                args.mode,
                "--max-pages",
                str(args.max_pages),
                "--timeout",
                str(args.timeout),
                "--delay",
                str(args.delay),
                "--retries",
                str(args.retries),
            ],
            True,
        )
    ]
    provider_flags = []
    if args.providers:
        provider_flags = ["--providers", args.providers]
    if args.with_ai:
        steps.append(Step("AI discovery", [py, "ai_discovery_cli.py", "--input", "reports/output/evidence.json", *provider_flags], False))
    if args.with_mythic:
        steps.append(Step("Mythic Hunter validation", [py, "mythic_hunter_cli.py", "--input", "reports/output/evidence.json", "--depth", "DEEP_HUNTER_MODE"], False))
    if args.with_uplift:
        steps.append(Step("Advanced uplift analysis", [py, "mythic_uplift_cli.py", "--input", "reports/output/evidence.json"], False))
    if args.export:
        export_file = Path("export_reports.py")
        if export_file.exists():
            steps.append(Step("Export reports ZIP", [py, "export_reports.py"], False))
        else:
            steps.append(Step("Export reports ZIP missing", [py, "-c", "print('export_reports.py not found. Pull latest repo first.')"], False))
    return steps


def print_banner(args: argparse.Namespace, steps: Sequence[Step]) -> None:
    print("┌──────────────────────── VulnScope Agentic Kali Mode ────────────────────────┐")
    print("│ Safe authorized workflow orchestration                                       │")
    print("│ It runs scanner, AI discovery, validation, uplift analysis, and export.       │")
    print("│ It does not perform exploitation, credential capture, or destructive actions. │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")
    print(f"Target      : {args.url}")
    print(f"Mode        : {args.mode}")
    print(f"Max pages   : {args.max_pages}")
    print(f"Timeout     : {args.timeout}s")
    print(f"Delay       : {args.delay}s")
    print(f"Retries     : {args.retries}")
    print("\nPlanned steps:")
    for index, step in enumerate(steps, start=1):
        required = "required" if step.required else "optional"
        print(f"{index:02d}. {step.name} ({required})")
        print("    " + " ".join(step.command))


if __name__ == "__main__":
    raise SystemExit(main())
