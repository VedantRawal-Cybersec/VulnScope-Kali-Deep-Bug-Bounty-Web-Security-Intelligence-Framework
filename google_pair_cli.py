#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from auth.credential_store import load_all_profiles

OUT = Path("reports/output/google-pair")

PHASES = [
    ("Google login both accounts", "python3 auth_mode.py --profile {profile} --google-login --account both"),
    ("Crawl account A", "python3 auth_mode.py --profile {profile} --crawl --account a --max-pages {max_pages}"),
    ("Crawl account B", "python3 auth_mode.py --profile {profile} --crawl --account b --max-pages {max_pages}"),
    ("Compare accounts", "python3 auth_mode.py --profile {profile} --compare-accounts"),
    ("Google context review", "python3 google_context_cli.py"),
    ("Auth differential v2", "python3 auth_diff_v2_cli.py"),
    ("Normalize evidence", "python3 normalize_cli.py --target {target}"),
    ("API intelligence", "python3 api_intel_cli.py --target {target}"),
    ("Asset graph", "python3 asset_graph_cli.py --target {target}"),
    ("Evidence cards", "python3 evidence_cards_cli.py --target {target}"),
    ("Reportability", "python3 reportability_cli.py --target {target}"),
]
SETUP_HELP = [
    "python3 auth_mode.py --setup-google-profile",
    "python3 auth_mode.py --profile default --persistent-google-login --account both",
]


def run(command: str, timeout: int = 1800) -> dict:
    started = time.time()
    p = subprocess.run(["bash", "-lc", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return {"command": command, "ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - started, 2), "output_tail": p.stdout[-2500:]}


def profile_exists(profile: str) -> bool:
    return profile in load_all_profiles(raw=True)


def write_payload(payload: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "google-pair-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope two-Google-account precision workflow")
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--skip-login", action="store_true", help="Use existing saved Google storage states")
    parser.add_argument("--skip-if-missing", action="store_true", help="Return success with skipped status if the auth profile does not exist")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    if not profile_exists(args.profile):
        payload = {"target": args.target, "profile": args.profile, "ok": False, "skipped": args.skip_if_missing, "reason": "auth_profile_missing", "setup_required": True, "setup_help": SETUP_HELP, "history": []}
        write_payload(payload)
        print(json.dumps({"ok": args.skip_if_missing, "skipped": args.skip_if_missing, "reason": "auth_profile_missing", "setup_help": SETUP_HELP, "output": "reports/output/google-pair/google-pair-run.json"}, indent=2))
        return 0 if args.skip_if_missing else 1

    if not args.yes:
        ans = input("Confirm both Google accounts are yours/test accounts and authorized for this target? yes/no: ").strip().lower()
        if ans not in {"yes", "y"}:
            print(json.dumps({"started": False, "reason": "authorization not confirmed"}, indent=2))
            return 1

    history = []
    failed = False
    failed_label = None
    for label, template in PHASES:
        if args.skip_login and label == "Google login both accounts":
            history.append({"label": label, "skipped": True, "reason": "--skip-login"})
            continue
        command = template.format(profile=args.profile, max_pages=args.max_pages, target=args.target)
        print(f"\n[Google Pair] {label}")
        result = run(command)
        print(result.get("output_tail", "")[-1500:])
        history.append({"label": label, "result": result})
        if not result.get("ok"):
            failed = True
            failed_label = label
            break

    payload = {"target": args.target, "profile": args.profile, "max_pages": args.max_pages, "ok": not failed, "skipped": False, "failed_label": failed_label, "history": history, "setup_required": failed, "setup_help": SETUP_HELP if failed else [], "outputs": {
        "account_compare": "reports/output/auth/account-comparison.md",
        "google_context": "reports/output/auth/google-context/google-context-review.md",
        "auth_diff_v2": "reports/output/auth/differential-v2/auth-diff-v2.md",
        "evidence_cards": "reports/output/evidence-cards/evidence-cards.md",
        "reportability": "reports/output/reportability/reportability.md",
    }}
    write_payload(payload)
    print(json.dumps({"ok": not failed, "output": "reports/output/google-pair/google-pair-run.json", "phases": len(history), "failed_label": failed_label}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
