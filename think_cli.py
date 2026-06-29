#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess

from autonomy.decision_engine import build_decision_plan
from scope.policy import load_scope_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope autonomous thinking / next-action planner")
    parser.add_argument("--target", required=True, help="Owned or explicitly authorized target URL/domain")
    parser.add_argument("--mode", default="comprehensive")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    parser.add_argument("--execute-next", action="store_true", help="Execute only the next safe recommended VulnScope command")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    decision = load_scope_policy(args.scope_policy).check(args.target)
    if not decision.allowed:
        print(json.dumps({"allowed": False, "reason": decision.reason}, indent=2))
        return 1
    plan = build_decision_plan(args.target, provider=args.provider, mode=args.mode)
    print(json.dumps({"next_action": plan.get("next_action"), "output": "reports/output/autonomy/decision-plan.md"}, indent=2))
    if args.execute_next and plan.get("next_action"):
        if not args.yes:
            answer = input("Execute the next recommended safe VulnScope command? yes/no: ").strip().lower()
            if answer not in {"yes", "y"}:
                return 0
        command = plan["next_action"]["command"]
        return subprocess.call(["bash", "-lc", command])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
