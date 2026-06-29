#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from history.target_history import save_history


def main() -> int:
    parser = argparse.ArgumentParser(description="Save VulnScope target history and diff")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    result = save_history(args.target)
    print(json.dumps({"diff": result["diff"], "history_dir": result["history_dir"], "report": "reports/output/history/last-run.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
