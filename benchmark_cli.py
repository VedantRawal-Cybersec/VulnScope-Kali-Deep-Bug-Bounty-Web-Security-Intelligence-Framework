#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from benchmark.lab_targets import list_labs
from benchmark.runner import run_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VulnScope benchmark on local authorized labs")
    parser.add_argument("--list", action="store_true", help="List supported benchmark labs")
    parser.add_argument("--lab", default="juice-shop-local", help="Lab key")
    parser.add_argument("--target", help="Override target URL")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "pentest", "comprehensive", "learning"])
    parser.add_argument("--no-council", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.list:
        print(json.dumps(list_labs(), indent=2))
        return 0
    result = run_benchmark(args.lab, target=args.target, mode=args.mode, council=not args.no_council, dry_run=args.dry_run)
    print(json.dumps(result.to_dict(), indent=2))
    return result.return_code


if __name__ == "__main__":
    raise SystemExit(main())
