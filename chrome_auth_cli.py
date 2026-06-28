#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from auth.chrome_profile_crawler import crawl_with_chrome_profile, compare_chrome_profile_crawls

DEFAULT_ROOT = Path.home() / ".vulnscope" / "google_profiles"


def main() -> int:
    parser = argparse.ArgumentParser(description="Use saved Chrome Google profiles for authorized authenticated review")
    parser.add_argument("--target", required=True, help="Authorized target URL, e.g. https://example.com")
    parser.add_argument("--account", choices=["a", "b", "both"], default="both")
    parser.add_argument("--account-a-dir", default=str(DEFAULT_ROOT / "account_a"))
    parser.add_argument("--account-b-dir", default=str(DEFAULT_ROOT / "account_b"))
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--compare", action="store_true", help="Compare account A and B crawl outputs after crawl")
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    print("┌──────────── Chrome Profile Auth Review ────────────┐")
    print("│ Uses your existing local Chrome profiles.           │")
    print("│ Does not collect or extract Google passwords.       │")
    print("│ Same-origin navigation/link collection only.        │")
    print("└─────────────────────────────────────────────────────┘")
    print(f"Target: {args.target}")

    outputs = []
    if args.account in {"a", "both"}:
        print(f"\n[+] Crawling with account_a profile: {args.account_a_dir}")
        outputs.append(crawl_with_chrome_profile("account_a", args.target, args.account_a_dir, max_pages=args.max_pages, headless=args.headless))
    if args.account in {"b", "both"}:
        print(f"\n[+] Crawling with account_b profile: {args.account_b_dir}")
        outputs.append(crawl_with_chrome_profile("account_b", args.target, args.account_b_dir, max_pages=args.max_pages, headless=args.headless))

    print("\n[+] Crawl complete.")
    for item in outputs:
        print(f"[+] {item['config']['label']}: pages={item['page_count']} requests={item['request_count']}")

    if args.compare or args.account == "both":
        comparison = compare_chrome_profile_crawls("account_a", "account_b")
        print("[+] Comparison written:")
        print("    reports/output/auth/chrome-profile-account-comparison.json")
        print("    reports/output/auth/chrome-profile-account-comparison.md")
        print(json.dumps({
            "only_account_a_urls": len(comparison.get("only_account_a_urls", [])),
            "only_account_b_urls": len(comparison.get("only_account_b_urls", [])),
            "common_urls": len(comparison.get("common_urls", [])),
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
