#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from graph.asset_graph import build_asset_graph


def main() -> int:
    parser = argparse.ArgumentParser(description="Build VulnScope unified asset graph")
    parser.add_argument("--target")
    args = parser.parse_args()
    result = build_asset_graph(args.target)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/asset-graph/asset-graph.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
