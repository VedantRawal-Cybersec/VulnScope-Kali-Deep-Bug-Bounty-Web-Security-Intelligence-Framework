#!/usr/bin/env python3
from __future__ import annotations

import argparse
from evidence_graph.graph_builder import save_evidence_graph


def main() -> int:
    parser = argparse.ArgumentParser(description="Build VulnScope evidence graph")
    parser.add_argument("--out", default="reports/output/evidence-graph/evidence-graph.json")
    args = parser.parse_args()
    out = save_evidence_graph(args.out)
    print(f"[+] Evidence graph: {out}")
    print(f"[+] Evidence graph summary: {out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
