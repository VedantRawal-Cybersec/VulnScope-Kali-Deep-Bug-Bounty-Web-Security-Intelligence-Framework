#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from autonomy.tool_brain import build_tool_brain_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope smart tool selector")
    parser.add_argument("--target")
    args = parser.parse_args()
    result = build_tool_brain_plan(args.target)
    print(json.dumps({"actions": len(result["actions"]), "report": "reports/output/tool-brain/tool-brain-plan.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
