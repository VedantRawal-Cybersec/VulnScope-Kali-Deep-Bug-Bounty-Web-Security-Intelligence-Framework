#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from findings.quality import load_findings_from_reports, reduce_low_quality


def main() -> int:
    parser = argparse.ArgumentParser(description="Deduplicate and quality-score VulnScope findings")
    parser.add_argument("--input", action="append", default=[], help="JSON report path. Can be used multiple times")
    parser.add_argument("--threshold", type=float, default=0.45)
    parser.add_argument("--out", default="reports/output/finding-quality.json")
    args = parser.parse_args()
    paths = args.input or [
        "reports/output/agent_core/agent-core-summary.json",
        "reports/output/workflow/reportability-scores.json",
        "reports/output/imports/har-import.json",
    ]
    items = load_findings_from_reports(paths)
    result = reduce_low_quality(items, threshold=args.threshold)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Quality output: {out}")
    print(json.dumps(result.get("summary", {}), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
