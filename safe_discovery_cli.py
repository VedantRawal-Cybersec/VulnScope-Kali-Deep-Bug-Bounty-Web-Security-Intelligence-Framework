#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from vuln_discovery.safe_finder import run_safe_discovery


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe non-exploit vulnerability discovery")
    parser.add_argument("--target", required=True, help="Owned or explicitly authorized target")
    parser.add_argument("--har-import", help="Optional HAR file for passive evidence review")
    parser.add_argument("--no-probes", action="store_true", help="Use only HAR/passive evidence; do not request /, robots.txt, sitemap.xml")
    args = parser.parse_args()
    result = run_safe_discovery(args.target, har_path=args.har_import, allow_probes=not args.no_probes)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("[+] Markdown: reports/output/vuln-discovery/safe-vulnerability-candidates.md")
    print("[+] JSON: reports/output/vuln-discovery/safe-vulnerability-candidates.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
