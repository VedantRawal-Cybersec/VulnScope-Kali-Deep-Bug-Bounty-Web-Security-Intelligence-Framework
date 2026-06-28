#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from auth.credential_store import load_profile, setup_google_oauth_profile
from auth.persistent_google_profiles import ensure_persistent_google_profile, list_persistent_profiles, open_persistent_profile
from auth.playwright_login import read_state_summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple persistent Google profile launcher for owned accounts")
    parser.add_argument("--setup", action="store_true", help="Create app/profile metadata for two Google accounts")
    parser.add_argument("--save", action="store_true", help="Open Google login windows and save persistent local profiles")
    parser.add_argument("--open", action="store_true", help="Open saved persistent local profile")
    parser.add_argument("--list", action="store_true", help="List saved persistent profiles")
    parser.add_argument("--crawl", action="store_true", help="Crawl with saved profiles after login")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--target-url", default="")
    parser.add_argument("--login-url", default="")
    parser.add_argument("--account-a-email", default="")
    parser.add_argument("--account-b-email", default="")
    parser.add_argument("--account", choices=["a", "b", "both"], default="both")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    if args.setup:
        setup_google_oauth_profile(
            name=args.profile,
            target_url=args.target_url or None,
            login_url=args.login_url or None,
            account_a_email=args.account_a_email or None,
            account_b_email=args.account_b_email or None,
            interactive=not (args.target_url and args.login_url and args.account_a_email),
        )
        print("[+] Setup complete. Now run: python3 google_profiles_cli.py --save --account both")
        return 0

    if args.list:
        print(json.dumps(list_persistent_profiles(args.profile), indent=2))
        return 0

    profile = load_profile(args.profile)

    if args.save:
        print("[+] A real Google/target login window will open. Enter email/password only inside that browser window.")
        print("[+] VulnScope will save the local browser profile, not your Google password.")
        if args.account in {"a", "both"}:
            state = ensure_persistent_google_profile(profile, "account_a", headless=args.headless)
            print(read_state_summary(state))
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured. Run --setup with --account-b-email or use interactive setup.")
                return 1
            state = ensure_persistent_google_profile(profile, "account_b", headless=args.headless)
            print(read_state_summary(state))
        print("[+] Saved. Later use: python3 google_profiles_cli.py --open --account a")
        return 0

    if args.open:
        if args.account in {"a", "both"}:
            open_persistent_profile(profile, "account_a", headless=args.headless)
        if args.account in {"b", "both"}:
            if not profile.account_b:
                print("[!] Account B not configured")
                return 1
            open_persistent_profile(profile, "account_b", headless=args.headless)
        return 0

    if args.crawl:
        command = ["python3", "auth_mode.py", "--profile", args.profile, "--crawl", "--account", args.account, "--max-pages", str(args.max_pages)]
        return subprocess.call(command)

    print("Use one of: --setup, --save, --open, --list, --crawl")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
