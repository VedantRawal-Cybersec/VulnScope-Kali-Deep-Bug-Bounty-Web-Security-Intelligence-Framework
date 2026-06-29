#!/usr/bin/env python3
from __future__ import annotations

import json

from auth.google_context_review import GoogleContextReview


def main() -> int:
    result = GoogleContextReview().run()
    print(json.dumps({"summary": result["summary"], "output": "reports/output/auth/google-context/google-context-review.json"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
