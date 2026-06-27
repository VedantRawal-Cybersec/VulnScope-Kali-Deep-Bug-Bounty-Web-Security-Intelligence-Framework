#!/usr/bin/env python3
"""
VulnScope-Kali v0.1.0-alpha
Authorized Web Security Intelligence Framework for Kali Linux.

Phase 1 provides safe passive assessment, same-domain crawling,
header/cookie checks, endpoint discovery, parameter mapping, and reports.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from core.authorization_guard import confirm_authorization
from core.banner import print_banner
from core.orchestrator import VulnScopeScanner
from core.validators import validate_target_url

VERSION = "0.1.0-alpha"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VulnScope-Kali: Deep Bug Bounty Web Security Intelligence Framework"
    )
    parser.add_argument("--url", help="Target URL, for example https://example.com")
    parser.add_argument(
        "--mode",
        choices=["passive", "safe-active"],
        help="Scan mode. Phase 1 supports passive and safe-active.",
    )
    parser.add_argument("--max-pages", type=int, default=30, help="Maximum pages to crawl")
    parser.add_argument(
        "--output-dir",
        default="reports/output",
        help="Directory where reports will be written",
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


def main() -> int:
    args = parse_args()
    print_banner(VERSION)

    raw_url = args.url or ask_for_url()
    target = validate_target_url(raw_url)

    print(f"\n[+] Target received : {target.normalized_url}")
    print(f"[+] Scheme          : {target.scheme.upper()}")
    print(f"[+] Host            : {target.host}")
    print("[+] Scope           : Same-domain only")

    if not confirm_authorization(target.normalized_url):
        print("\n[!] Authorization not confirmed.")
        print("[!] Scan cancelled for safety.")
        return 1

    mode = args.mode or ask_for_mode()

    print("\n┌────────────────────────────── Scan Configuration ────────────────────────────┐")
    print(f"│ Target URL       : {target.normalized_url[:56]:<56} │")
    print(f"│ Scan Mode        : {mode:<56} │")
    print(f"│ Crawl Scope      : {'Same domain only':<56} │")
    print(f"│ Max Pages        : {str(args.max_pages):<56} │")
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
    )
    scanner.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
