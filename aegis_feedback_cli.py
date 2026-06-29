#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from aegis.feedback_loop import build_feedback_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS-SAFE feedback planner")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    result = build_feedback_plan(args.target)
    print(json.dumps({"signals": result["signals"], "actions": len(result["actions"]), "report": "reports/output/aegis/feedback/feedback-plan.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
