#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dashboard.live_dashboard import run_dashboard


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope live terminal dashboard")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--refresh", type=float, default=2.0)
    args = parser.parse_args()
    run_dashboard(refresh=args.refresh, once=args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
