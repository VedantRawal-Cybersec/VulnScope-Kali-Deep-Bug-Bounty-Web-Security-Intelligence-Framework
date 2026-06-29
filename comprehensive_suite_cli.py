#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from scope.policy import load_scope_policy
from vuln_categories.comprehensive_suite import ComprehensiveCategorySuite


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope comprehensive safe category review")
    parser.add_argument("--target", required=True, help="Owned or explicitly authorized target URL/domain")
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    parser.add_argument("--yes", action="store_true", help="Confirm authorization non-interactively")
    args = parser.parse_args()

    decision = load_scope_policy(args.scope_policy).check(args.target)
    if not decision.allowed:
        print(json.dumps({"allowed": False, "reason": decision.reason}, indent=2))
        return 1
    if not args.yes:
        answer = input("Confirm this target is owned or authorized for comprehensive review? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print("[!] Cancelled")
            return 1
    result = ComprehensiveCategorySuite(target=args.target).run()
    print(json.dumps({"target": result["target"], "summary": result["summary"], "output": "reports/output/comprehensive-suite/comprehensive-suite.json"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
