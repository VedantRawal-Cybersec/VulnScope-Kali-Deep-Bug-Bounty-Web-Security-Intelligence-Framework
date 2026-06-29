#!/usr/bin/env python3
from __future__ import annotations

import json
from auth.differential_engine import build_auth_diff_v2


def main() -> int:
    result = build_auth_diff_v2()
    print(json.dumps({"summary": result["summary"], "report": "reports/output/auth/differential-v2/auth-diff-v2.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
