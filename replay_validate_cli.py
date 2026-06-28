#!/usr/bin/env python3
from __future__ import annotations

import argparse
from validation.replay_validator import save_replay_validation


def main() -> int:
    parser = argparse.ArgumentParser(description="Run controlled safe replay validation for authorized endpoints")
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    parser.add_argument("--max-requests", type=int, default=25)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", default="reports/output/validation/replay-validation.json")
    args = parser.parse_args()
    out = save_replay_validation(args.out, scope_policy_path=args.scope_policy, max_requests=args.max_requests, timeout=args.timeout, dry_run=args.dry_run)
    print(f"[+] Replay validation output: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
