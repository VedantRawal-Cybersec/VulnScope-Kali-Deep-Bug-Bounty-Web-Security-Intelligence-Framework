#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from findings.reportability import build_reportability


def main() -> int:
    parser = argparse.ArgumentParser(description="Rank VulnScope candidates by reportability")
    parser.add_argument("--target")
    args = parser.parse_args()
    result = build_reportability(args.target)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/reportability/reportability.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
