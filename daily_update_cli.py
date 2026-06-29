#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from maintenance.daily_update import run_daily_update, update_if_due


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope daily maintenance updater")
    parser.add_argument("--profile", default=None, help="Optional arsenal profile")
    parser.add_argument("--force", action="store_true", help="Run even if the daily update already ran recently")
    parser.add_argument("--yes", action="store_true", help="Allow approved automatic local install/update steps")
    args = parser.parse_args()

    if args.force:
        result = run_daily_update(profile=args.profile, yes=args.yes)
    else:
        result = update_if_due(profile=args.profile, yes=args.yes)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
