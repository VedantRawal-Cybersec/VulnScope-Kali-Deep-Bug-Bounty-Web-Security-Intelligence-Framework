#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from mythic_hunter.engine import run_acceptance_tests, run_mythic_text

VERSION = "0.4.0-alpha"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mythic Hunter Validation Engine")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--input", help="Local text, JSON, markdown, HAR-like, JS, headers, or scanner output file")
    parser.add_argument("--text", help="Short direct input text")
    parser.add_argument("--run-tests", action="store_true", help="Run built-in acceptance tests")
    parser.add_argument(
        "--depth",
        default="BALANCED_VALIDATION",
        choices=["QUICK_TRIAGE", "BALANCED_VALIDATION", "DEEP_HUNTER_MODE", "PARANOID_FALSE_POSITIVE_REVIEW"],
        help="Reasoning depth",
    )
    parser.add_argument(
        "--report-type",
        default="bug_bounty_report",
        choices=["bug_bounty_report", "internal_security_report", "false_positive_elimination_report", "scanner_validation_report", "portfolio_proof"],
        help="Report mode",
    )
    parser.add_argument("--output-dir", default="reports/output/mythic", help="Output directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"Mythic Hunter Validation Engine {VERSION}")
        return 0

    if args.run_tests:
        tests = run_acceptance_tests(output_dir=args.output_dir)
        passed = sum(1 for item in tests if item.get("passed"))
        print(f"[+] Acceptance tests: {passed}/{len(tests)} passed")
        print(f"[+] Output: {args.output_dir}/mythic-acceptance-tests.json")
        return 0 if passed == len(tests) else 1

    if args.text:
        text = args.text
    elif args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"[!] Input file not found: {path}")
            return 1
        text = path.read_text(encoding="utf-8", errors="ignore")
    else:
        print("[!] Provide --input, --text, or --run-tests")
        return 1

    result = run_mythic_text(text=text, output_dir=args.output_dir, depth=args.depth, report_type=args.report_type)
    print("[+] Mythic Hunter analysis completed")
    print(f"[+] Findings: {len(result.findings)}")
    print(f"[+] Endpoints: {len(result.endpoints)}")
    print(f"[+] Reportable candidates: {result.dashboard.get('Reportable Candidates', 0)}")
    print(f"[+] Markdown report: {args.output_dir}/mythic-report.md")
    print(f"[+] Evidence JSON: {args.output_dir}/mythic-evidence.json")
    print(f"[+] Proof exports: {args.output_dir}/mythic-proof-exports.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
