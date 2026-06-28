#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from auth.account_comparator import compare_account_crawls
from auth.auth_crawler import crawl_authenticated
from auth.credential_store import list_profiles, load_profile, redacted_profile_summary, setup_auth_profile
from auth.playwright_login import save_login_state, read_state_summary

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated Manual Validation Mode for owned test accounts")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--setup-accounts", action="store_true")
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--login", action="store_true", help="Open browser login and save session state")
    parser.add_argument("--crawl", action="store_true", help="Crawl authenticated pages with saved session")
    parser.add_argument("--compare-accounts", action="store_true", help="Compare Account A and Account B crawl samples")
    parser.add_argument("--full-auth", action="store_true", help="Login A/B if configured, crawl, then compare")
    parser.add_argument("--account", choices=["a", "b", "both"], default="a")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--headless", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"Authenticated Validation Mode {VERSION}")
        return 0
    if args.setup_accounts:
        setup_auth_profile()
        return 0
    if args.list_profiles:
        for profile in list_profiles():
            print(profile)
        return 0

    profile = load_profile(args.profile)
    print("┌──────────── Authenticated Manual Validation Mode ────────────┐")
    print("│ Owned test accounts only. Credentials stay local.             │")
    print("│ OTP/CAPTCHA/manual login is handled by pausing the browser.   │")
    print("└───────────────────────────────────────────────────────────────┘")
    print(redacted_profile_summary(args.profile))

    if args.full_auth:
        login_and_crawl(profile, "a", args.max_pages, args.headless)
        if profile.account_b:
            login_and_crawl(profile, "b", args.max_pages, args.headless)
            compare_account_crawls("reports/output/auth/auth-crawl-account_a.json", "reports/output/auth/auth-crawl-account_b.json")
        else:
            print("[!] Account B not configured. Skipping comparison.")
        return 0

    if args.login:
        if args.account in {"a", "both"}:
            state = save_login_state(profile, profile.account_a, headless=args.headless)
            print(read_state_summary(state))
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured")
                return 1
            state = save_login_state(profile, profile.account_b, headless=args.headless)
            print(read_state_summary(state))
        return 0

    if args.crawl:
        if args.account in {"a", "both"}:
            state = Path(f"reports/output/auth/states/{profile.name}-account_a.json")
            crawl_authenticated(profile.target_url, state, "account_a", max_pages=args.max_pages, headless=args.headless)
        if args.account in {"b", "both"}:
            state = Path(f"reports/output/auth/states/{profile.name}-account_b.json")
            crawl_authenticated(profile.target_url, state, "account_b", max_pages=args.max_pages, headless=args.headless)
        return 0

    if args.compare_accounts:
        compare_account_crawls("reports/output/auth/auth-crawl-account_a.json", "reports/output/auth/auth-crawl-account_b.json")
        return 0

    print("[!] No action selected. Use --setup-accounts, --login, --crawl, --compare-accounts, or --full-auth")
    return 1


def login_and_crawl(profile, account_name: str, max_pages: int, headless: bool) -> None:
    account = profile.account_a if account_name == "a" else profile.account_b
    if account is None:
        return
    state = save_login_state(profile, account, headless=headless)
    print(read_state_summary(state))
    crawl_authenticated(profile.target_url, state, account.label, max_pages=max_pages, headless=headless)


if __name__ == "__main__":
    raise SystemExit(main())
