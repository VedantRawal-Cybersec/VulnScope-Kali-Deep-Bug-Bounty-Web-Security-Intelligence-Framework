#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from recon.domain_expander import run_passive_domain_expansion

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive subdomain and archived URL intelligence")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", help="Domain or URL to expand")
    parser.add_argument("--no-tools", action="store_true", help="Skip local tools and use crt.sh only")
    parser.add_argument("--max-urls", type=int, default=5000)
    parser.add_argument("--scan-discovered", action="store_true", help="Run VulnScope passive scan on discovered subdomains after explicit confirmation")
    parser.add_argument("--max-subdomains", type=int, default=10, help="Limit active scans when --scan-discovered is used")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"Domain Recon CLI {VERSION}")
        return 0
    if not args.target:
        print("[!] Provide --target example.com or https://example.com")
        return 1

    result = run_passive_domain_expansion(args.target, include_external_tools=not args.no_tools, max_urls=args.max_urls)
    print("┌──────────────── Passive Domain Expansion Complete ────────────────┐")
    print(f"Root domain      : {result.root_domain}")
    print(f"Subdomains       : {len(result.subdomains)}")
    print(f"Archived URLs    : {len(result.archived_urls)}")
    print(f"Review candidates: {len(result.high_value_urls)}")
    print("└───────────────────────────────────────────────────────────────────┘")
    print("Reports:")
    print("- reports/output/recon/domain-expansion.md")
    print("- reports/output/recon/domain-expansion.json")
    print("- reports/output/recon/subdomains.txt")
    print("- reports/output/recon/archived-urls.txt")
    print("- reports/output/recon/high-value-urls.json")

    if args.scan_discovered:
        return scan_discovered(result.subdomains[: args.max_subdomains], args)
    return 0


def scan_discovered(subdomains: list[str], args: argparse.Namespace) -> int:
    if not subdomains:
        print("[!] No subdomains to scan")
        return 0
    print("\n[!] Active/passive HTTP scans against discovered subdomains require explicit authorization.")
    print(f"[!] Planned subdomain scan count: {len(subdomains)}")
    answer = input("Confirm all listed subdomains are in scope? yes/no: ").strip().lower()
    if answer not in {"yes", "y"}:
        print("[!] Cancelled subdomain scans")
        return 1
    py = sys.executable or "python3"
    out_base = Path("reports/output/subdomain-scans")
    out_base.mkdir(parents=True, exist_ok=True)
    for host in subdomains:
        url = f"https://{host}"
        out = out_base / host.replace("/", "_")
        command = [py, "vulnscope.py", "--url", url, "--mode", "passive", "--max-pages", "3", "--timeout", str(args.timeout), "--delay", str(args.delay), "--retries", str(args.retries), "--output-dir", str(out)]
        print("\n[+] " + " ".join(command))
        subprocess.call(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
