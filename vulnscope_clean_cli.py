#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys

import kai_flow_core


def main() -> int:
    if os.getenv("VULNSCOPE_SKIP_TOOL_SETUP", "0") != "1":
        subprocess.call([sys.executable, "safe_tool_setup_cli.py", "--yes"])
    return int(kai_flow_core.main())


if __name__ == "__main__":
    raise SystemExit(main())
