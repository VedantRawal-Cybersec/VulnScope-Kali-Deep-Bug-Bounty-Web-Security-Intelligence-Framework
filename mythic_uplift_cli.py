#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from mythic_hunter.uplift_modules import analyze_uplift_text

VERSION = "0.1.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope advanced uplift analyzer")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--input", help="Input file: HAR, Burp text, Postman, OpenAPI, headers, JS, endpoint list, or scanner output")
    parser.add_argument("--text", help="Short text input")
    parser.add_argument("--output-dir", default="reports/output/uplift")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Uplift CLI {VERSION}")
        return 0
    if args.text:
        text = args.text
    elif args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"[!] Input file not found: {path}")
            return 1
        text = path.read_text(encoding="utf-8", errors="ignore")
    else:
        print("[!] Provide --input or --text")
        return 1
    result = analyze_uplift_text(text, output_dir=args.output_dir)
    print("[+] Uplift analysis completed")
    print(f"[+] Endpoints: {len(result.imports.get('endpoints', []))}")
    print(f"[+] Findings: {len(result.findings)}")
    print(f"[+] Object flows: {len(result.object_flows)}")
    print(f"[+] State-changing actions: {len(result.state_actions)}")
    print(f"[+] OpenAPI routes: {len(result.openapi)}")
    print(f"[+] Report: {args.output_dir}/uplift-report.md")
    print(f"[+] Evidence: {args.output_dir}/uplift-evidence.json")
    print(f"[+] Defensive exports: {args.output_dir}/defensive-exports.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
