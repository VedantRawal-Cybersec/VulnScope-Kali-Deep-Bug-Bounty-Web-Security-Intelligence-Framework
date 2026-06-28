#!/usr/bin/env python3
from __future__ import annotations

import argparse

from agent.controller import AgenticController, ControllerConfig

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope Agentic Controller - guided AI Kali workflow")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--url", help="Authorized target URL")
    parser.add_argument("--mode", default="passive", choices=["passive", "safe-active"])
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--providers", default="", help="AI providers: openai,gemini,groq,openrouter")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI Discovery")
    parser.add_argument("--no-validation", action="store_true", help="Skip Mythic validation")
    parser.add_argument("--no-uplift", action="store_true", help="Skip advanced uplift analysis")
    parser.add_argument("--no-export", action="store_true", help="Skip report ZIP export")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    parser.add_argument("--yes", action="store_true", help="Auto-approve internal/passive steps")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Agentic Controller {VERSION}")
        return 0
    if not args.url:
        print("[!] Provide an authorized target with --url")
        return 1
    config = ControllerConfig(
        target_url=args.url,
        mode=args.mode,
        max_pages=args.max_pages,
        timeout=args.timeout,
        delay=args.delay,
        retries=args.retries,
        providers=args.providers,
        yes=args.yes,
        dry_run=args.dry_run,
        run_ai=not args.no_ai,
        run_validation=not args.no_validation,
        run_uplift=not args.no_uplift,
        export_reports=not args.no_export,
    )
    print("┌──────────────────── VulnScope Agentic Controller ────────────────────┐")
    print("│ One guided workflow: scan → AI discovery → validation → uplift → ZIP  │")
    print("│ Approval gates remain active for safety and scope control.            │")
    print("└──────────────────────────────────────────────────────────────────────┘")
    return AgenticController(config).run()


if __name__ == "__main__":
    raise SystemExit(main())
