#!/usr/bin/env python3
from __future__ import annotations

import argparse
from importers.har_importer import save_import


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Burp/browser HAR traffic into VulnScope evidence")
    parser.add_argument("--har", required=True, help="Path to HAR file exported from browser/Burp")
    parser.add_argument("--out", default="reports/output/imports/har-import.json")
    args = parser.parse_args()
    out = save_import(args.har, args.out)
    print(f"[+] HAR imported: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
