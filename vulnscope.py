#!/usr/bin/env python3
"""
VulnScope-Kali v0.3.2-alpha
Authorized Web Security Intelligence Framework for Kali Linux.

v0.3.2-alpha adds configurable HTTP timeout, delay, and retry controls for slow/CDN-heavy targets.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ai.key_setup import setup_ai_keys, show_ai_key_status
from ai.local_env import load_local_ai_env
from core.authorization_guard import confirm_authorization
from core.banner import print_banner
from core.orchestrator import VulnScopeScanner
from core.validators import validate_target_url

VERSION = "0.3.2-alpha"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VulnScope-Kali: Deep Bug Bounty Web Security Intelligence Framework"
    )
    parser.add_argument("--version", action="store_true", help="Show VulnScope-Kali version and exit")
    parser.add_argument("--setup-ai-keys", action="store_true", help="Interactively add AI provider API keys to local .env.local")
    parser.add_argument("--ai-key-status", action="store_true", help="Show which AI provider keys are configured without revealing values")
    parser.add_argument("--url", help="Target URL, for example https://example.com")
    parser.add_argument(
        "--mode",
        choices=["passive", "safe-active"],
        help="Scan mode. Current build supports passive and safe-active.",
    )
    parser.add_argument("--max-pages", type=int, default=30, help="Maximum pages to crawl")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP read timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.7, help="Delay between HTTP requests in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for transient HTTP errors and timeouts")
    parser.add_argument(
        "--output-dir",
        default="reports/output",
        help="Directory where reports will be written",
    )
    parser.add_argument(
        "--ai-review",
        action="store_true",
        help="Enable AI Analyst Engine on redacted evidence. Requires provider API keys in environment variables or .env.local.",
    )
    parser.add_argument(
        "--ai-providers",
        default="",
        help="Comma-separated providers: openai,gemini,groq,openrouter. Default: auto-detect from local config/environment.",
    )
    return parser.parse_args()


def ask_for_url() -> str:
    print("\n┌──────────────────────────── Target Configuration ────────────────────────────┐")
    print("│ Enter the authorized target URL                                               │")
    print("│ Example: https://example.com | http://localhost:3000                          │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")
    return input("\n[?] Target URL: ").strip()


def ask_for_mode() -> str:
    print("\n[1] Passive Recon Mode")
    print("[2] Safe Active Mode")
    choice = input("\n[?] Select scan mode [1/2]: ").strip()
    if choice == "2":
        return "safe-active"
    return "passive"


def parse_ai_providers(raw: str) -> list[str] | None:
    if not raw.strip():
        return None
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def main() -> int:
    load_local_ai_env()
    args = parse_args()

    if args.version:
        print(f"VulnScope-Kali {VERSION}")
        return 0

    if args.setup_ai_keys:
        setup_ai_keys()
        return 0

    if args.ai_key_status:
        show_ai_key_status()
        return 0

    print_banner(VERSION)

    raw_url = args.url or ask_for_url()
    target = validate_target_url(raw_url)

    print(f"\n[+] Target received : {target.normalized_url}")
    print(f"[+] Scheme          : {target.scheme.upper()}")
    print(f"[+] Host            : {target.host}")
    print("[+] Scope           : Same-domain only")
    print(f"[+] HTTP Timeout    : {args.timeout}s")
    print(f"[+] HTTP Delay      : {args.delay}s")
    print(f"[+] HTTP Retries    : {args.retries}")

    if args.ai_review:
        print("[+] AI Review       : Enabled, redacted evidence only")
    else:
        print("[+] AI Review       : Disabled")

    if not confirm_authorization(target.normalized_url):
        print("\n[!] Authorization not confirmed.")
        print("[!] Scan cancelled for safety.")
        return 1

    mode = args.mode or ask_for_mode()
    ai_providers = parse_ai_providers(args.ai_providers)

    print("\n┌────────────────────────────── Scan Configuration ────────────────────────────┐")
    print(f"│ Target URL       : {target.normalized_url[:56]:<56} │")
    print(f"│ Scan Mode        : {mode:<56} │")
    print(f"│ Crawl Scope      : {'Same domain only':<56} │")
    print(f"│ Max Pages        : {str(args.max_pages):<56} │")
    print(f"│ HTTP Timeout     : {(str(args.timeout) + 's'):<56} │")
    print(f"│ HTTP Delay       : {(str(args.delay) + 's'):<56} │")
    print(f"│ HTTP Retries     : {str(args.retries):<56} │")
    print(f"│ AI Review        : {str(args.ai_review):<56} │")
    print(f"│ Output Directory : {args.output_dir[:56]:<56} │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")

    start = input("\n[?] Start scan now? yes/no: ").strip().lower()
    if start not in {"yes", "y"}:
        print("\n[!] Scan cancelled by user.")
        return 1

    scanner = VulnScopeScanner(
        target=target,
        mode=mode,
        max_pages=args.max_pages,
        output_dir=Path(args.output_dir),
        ai_review=args.ai_review,
        ai_providers=ai_providers,
        timeout=args.timeout,
        delay=args.delay,
        retries=args.retries,
    )
    scanner.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
