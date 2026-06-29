#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from api_intel.engine import build_api_intel


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope API intelligence mapper")
    parser.add_argument("--target")
    args = parser.parse_args()
    result = build_api_intel(args.target)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/api-intel/api-intel.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
