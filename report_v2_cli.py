#!/usr/bin/env python3
from __future__ import annotations

import argparse
from reports.report_v2 import build_report_v2


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate VulnScope executive report v2")
    parser.add_argument("--target")
    args = parser.parse_args()
    outputs = build_report_v2(args.target)
    print(f"[+] Markdown report: {outputs['markdown']}")
    print(f"[+] JSON report: {outputs['json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
