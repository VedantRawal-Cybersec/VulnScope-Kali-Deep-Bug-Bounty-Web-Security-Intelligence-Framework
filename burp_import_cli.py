#!/usr/bin/env python3
from __future__ import annotations

import argparse
from importers.burp_importer import save_burp_import


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Burp Suite XML export into VulnScope evidence")
    parser.add_argument("--xml", required=True, help="Burp Suite XML export path")
    parser.add_argument("--out", default="reports/output/imports/burp-import.json")
    args = parser.parse_args()
    out = save_burp_import(args.xml, args.out)
    print(f"[+] Burp XML imported: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
