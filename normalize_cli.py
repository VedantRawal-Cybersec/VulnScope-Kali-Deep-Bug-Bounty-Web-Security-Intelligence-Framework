#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from normalizers.evidence import normalize_all


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize VulnScope outputs into one evidence model")
    parser.add_argument("--target")
    args = parser.parse_args()
    result = normalize_all(args.target)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/normalized/normalized-evidence.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
