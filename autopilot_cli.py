#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from autonomy.autonomy_policy import write_default_autonomy_policy
from autonomy.safe_runner import SafeAutonomyRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope safe autopilot for authorized workflows")
    parser.add_argument("--target", help="Authorized target URL/domain")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "pentest", "comprehensive", "learning"])
    parser.add_argument("--provider", help="Optional AI provider")
    parser.add_argument("--har-import", help="Optional HAR file path")
    parser.add_argument("--autonomy-policy", default="autonomy_policy.yaml")
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    parser.add_argument("--init-policy", action="store_true", help="Create default autonomy policy and exit")
    parser.add_argument("--yes", action="store_true", help="Confirm authorized scope non-interactively")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.init_policy:
        path = write_default_autonomy_policy(args.autonomy_policy)
        print(f"[+] Autonomy policy ready: {path}")
        return 0
    if not args.target:
        print("[!] Provide --target or use --init-policy")
        return 1
    if not args.yes:
        answer = input("Confirm this target is owned/authorized and allowed by scope policy? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print("[!] Cancelled")
            return 1
    result = SafeAutonomyRunner(target=args.target, mode=args.mode, autonomy_policy_path=args.autonomy_policy, scope_policy_path=args.scope_policy, har_path=args.har_import, provider=args.provider, auto_yes=args.yes, dry_run=args.dry_run).run()
    print(json.dumps({"target": result.get("target"), "scope": result.get("scope_decision"), "extra": result.get("extra")}, indent=2, ensure_ascii=False))
    print("[+] Autonomy run: reports/output/autonomy/autonomy-run.json")
    print("[+] Autonomy plan: reports/output/autonomy/autonomy-plan.md")
    return 0 if result.get("scope_decision", {}).get("allowed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
