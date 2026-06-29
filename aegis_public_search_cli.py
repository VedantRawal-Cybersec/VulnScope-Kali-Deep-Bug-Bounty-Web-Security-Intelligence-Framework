#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from urllib.parse import urlparse
from aegis.google_intelligence_safe import run_google_intel


def domain_from_target(value: str) -> str:
    parsed = urlparse(value if '://' in value else 'https://' + value)
    return parsed.netloc.split(':')[0].lower().strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS-SAFE public search review")
    parser.add_argument("--target", required=True)
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()
    result = run_google_intel(domain_from_target(args.target), args.limit)
    print(json.dumps({"summary": result["summary"], "configured": result["configured"], "report": "reports/output/aegis/google-intel/google-intel.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
