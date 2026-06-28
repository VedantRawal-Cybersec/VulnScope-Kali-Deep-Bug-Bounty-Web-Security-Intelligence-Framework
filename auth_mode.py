#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from auth.account_comparator import compare_account_crawls
from auth.auth_crawler import crawl_authenticated
from auth.credential_store import list_profiles, load_profile, redacted_profile_summary, setup_auth_profile, setup_google_oauth_profile
from auth.google_oauth_login import save_google_oauth_state
from auth.persistent_google_profiles import ensure_persistent_google_profile, list_persistent_profiles, open_persistent_profile, persistent_state_path
from auth.playwright_login import save_login_state, read_state_summary

VERSION = "1.3.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated Manual Validation Mode for owned test accounts")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--setup-accounts", action="store_true")
    parser.add_argument("--setup-google-profile", action="store_true", help="Create a Google/OAuth profile without storing passwords")
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--list-persistent-google", action="store_true", help="List persistent local Google browser profiles")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--target-url", default="", help="Target base URL for profile setup")
    parser.add_argument("--login-url", default="", help="Target login URL or Continue-with-Google page for profile setup")
    parser.add_argument("--account-a-email", default="", help="Account A email/label for Google/OAuth profile")
    parser.add_argument("--account-b-email", default="", help="Optional Account B email/label for Google/OAuth comparison")
    parser.add_argument("--login", action="store_true", help="Open browser login and save session state")
    parser.add_argument("--google-login", action="store_true", help="Open real browser for Google/OAuth login and save session state without storing Google password")
    parser.add_argument("--persistent-google-login", action="store_true", help="Create/reuse persistent local Chromium profiles for Google/OAuth accounts")
    parser.add_argument("--open-persistent-google", action="store_true", help="Open saved persistent Google browser profile for manual checks")
    parser.add_argument("--oauth-url", default="", help="Optional target-generated Google/OAuth URL. Prefer the target app's Continue with Google flow.")
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
    if args.setup_google_profile:
        setup_google_oauth_profile(
            name=args.profile,
            target_url=args.target_url or None,
            login_url=args.login_url or None,
            account_a_email=args.account_a_email or None,
            account_b_email=args.account_b_email or None,
            interactive=not (args.target_url and args.login_url and args.account_a_email),
        )
        return 0
    if args.list_profiles:
        profiles = list_profiles()
        if not profiles:
            print("[!] No auth profiles found.")
            print("[+] For Google/OAuth, run: python3 auth_mode.py --setup-google-profile")
            return 0
        for profile in profiles:
            print(profile)
        return 0
    if args.list_persistent_google:
        print(json.dumps(list_persistent_profiles(args.profile if args.profile else None), indent=2))
        return 0

    try:
        profile = load_profile(args.profile)
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        print("\nQuick fix for persistent Google/OAuth:")
        print("python3 auth_mode.py --setup-google-profile")
        print("\nNon-interactive example:")
        print("python3 auth_mode.py --setup-google-profile --profile default --target-url https://YOUR-APP.com --login-url https://YOUR-APP.com/login --account-a-email account-a@gmail.com --account-b-email account-b@gmail.com")
        print("\nThen save both persistent profiles:")
        print("python3 auth_mode.py --profile default --persistent-google-login --account both")
        return 1

    print("┌──────────── Authenticated Manual Validation Mode ────────────┐")
    print("│ Owned test accounts only. Credentials stay local.             │")
    print("│ Google/OAuth mode never asks for or stores Google passwords.  │")
    print("│ Persistent mode stores local Chromium profile/session data.   │")
    print("└───────────────────────────────────────────────────────────────┘")
    print(redacted_profile_summary(args.profile))

    if args.persistent_google_login:
        if args.account in {"a", "both"}:
            state = ensure_persistent_google_profile(profile, "account_a", oauth_url=args.oauth_url or None, headless=args.headless)
            print(read_state_summary(state))
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured")
                return 1
            state = ensure_persistent_google_profile(profile, "account_b", oauth_url=args.oauth_url or None, headless=args.headless)
            print(read_state_summary(state))
        print("[+] Persistent Google profiles saved locally under ~/.vulnscope/browser_profiles")
        print("[!] They remain usable until Google or the target app expires/revokes the session.")
        return 0

    if args.open_persistent_google:
        if args.account in {"a", "both"}:
            open_persistent_profile(profile, "account_a", headless=args.headless)
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured")
                return 1
            open_persistent_profile(profile, "account_b", headless=args.headless)
        return 0

    if args.google_login:
        if args.account in {"a", "both"}:
            state = save_google_oauth_state(profile, profile.account_a, oauth_url=args.oauth_url or None, headless=args.headless)
            print(read_state_summary(state))
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured")
                return 1
            state = save_google_oauth_state(profile, profile.account_b, oauth_url=args.oauth_url or None, headless=args.headless)
            print(read_state_summary(state))
        return 0

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
            state = _state_path(profile.name, "account_a")
            if not state.exists():
                print(f"[!] Saved session not found: {state}")
                print("[+] Run: python3 auth_mode.py --profile default --persistent-google-login --account a")
                return 1
            crawl_authenticated(profile.target_url, state, "account_a", max_pages=args.max_pages, headless=args.headless)
        if args.account in {"b", "both"}:
            state = _state_path(profile.name, "account_b")
            if not state.exists():
                print(f"[!] Saved session not found: {state}")
                print("[+] Run: python3 auth_mode.py --profile default --persistent-google-login --account b")
                return 1
            crawl_authenticated(profile.target_url, state, "account_b", max_pages=args.max_pages, headless=args.headless)
        return 0

    if args.compare_accounts:
        compare_account_crawls("reports/output/auth/auth-crawl-account_a.json", "reports/output/auth/auth-crawl-account_b.json")
        return 0

    print("[!] No action selected. Use --setup-google-profile, --persistent-google-login, --open-persistent-google, --crawl, --compare-accounts, or --full-auth")
    return 1


def _state_path(profile_name: str, account_label: str) -> Path:
    persistent_state = persistent_state_path(profile_name, account_label)
    google_state = Path(f"reports/output/auth/states/{profile_name}-{account_label}-google.json")
    normal_state = Path(f"reports/output/auth/states/{profile_name}-{account_label}.json")
    if persistent_state.exists():
        return persistent_state
    return google_state if google_state.exists() else normal_state


def login_and_crawl(profile, account_name: str, max_pages: int, headless: bool) -> None:
    account = profile.account_a if account_name == "a" else profile.account_b
    if account is None:
        return
    state = save_login_state(profile, account, headless=headless)
    print(read_state_summary(state))
    crawl_authenticated(profile.target_url, state, account.label, max_pages=max_pages, headless=headless)


if __name__ == "__main__":
    raise SystemExit(main())
