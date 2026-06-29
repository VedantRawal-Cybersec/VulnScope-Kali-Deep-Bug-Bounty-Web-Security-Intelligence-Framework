#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from artemis.burp_safe import run_burp_safe


def main() -> int:
    parser = argparse.ArgumentParser(description="ARTEMIS Burp Safe Bridge: scope seeds + passive finding import")
    parser.add_argument("--target")
    parser.add_argument("--limit", type=int, default=80)
    args = parser.parse_args()
    result = run_burp_safe(args.target, args.limit)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/artemis/burp-safe/burp-safe.md", "scope_seeds": "reports/output/artemis/burp-safe/burp-scope-seeds.txt"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
