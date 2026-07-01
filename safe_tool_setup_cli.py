#!/usr/bin/env python3
from __future__ import annotations

import sys

import fix_adapter_directory_cli
import tool_setup_dashboard_cli


def main() -> int:
    fix_adapter_directory_cli.main()
    original_argv = sys.argv[:]
    try:
        sys.argv = ["tool_setup_dashboard_cli.py", *original_argv[1:]]
        return int(tool_setup_dashboard_cli.main())
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    raise SystemExit(main())
