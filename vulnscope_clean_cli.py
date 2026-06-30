#!/usr/bin/env python3
from __future__ import annotations

import os

from tool_setup_dashboard_cli import run_tool_dashboard_gate
import kai_safe_interface


def main() -> int:
    if os.getenv("VULNSCOPE_SKIP_TOOL_SETUP", "0") != "1":
        run_tool_dashboard_gate(interactive=True, assume_yes=False)
    return int(kai_safe_interface.main())


if __name__ == "__main__":
    raise SystemExit(main())
