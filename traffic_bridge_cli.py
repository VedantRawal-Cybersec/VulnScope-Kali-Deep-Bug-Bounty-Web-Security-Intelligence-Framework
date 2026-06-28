#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidence_graph.graph_builder import save_evidence_graph
from importers.burp_importer import save_burp_import
from importers.har_importer import save_import as save_har_import


def main() -> int:
    parser = argparse.ArgumentParser(description="Traffic bridge: import proxy/browser exports and rebuild evidence graph")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--proxy-xml", help="Proxy XML export")
    group.add_argument("--har", help="HAR export")
    parser.add_argument("--graph", action="store_true", help="Rebuild evidence graph after import")
    args = parser.parse_args()
    outputs = {}
    if args.proxy_xml:
        outputs["proxy_import"] = str(save_burp_import(args.proxy_xml))
    if args.har:
        outputs["har_import"] = str(save_har_import(args.har))
    if args.graph:
        outputs["evidence_graph"] = str(save_evidence_graph())
    out = Path("reports/output/imports/bridge-summary.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(outputs, indent=2), encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
