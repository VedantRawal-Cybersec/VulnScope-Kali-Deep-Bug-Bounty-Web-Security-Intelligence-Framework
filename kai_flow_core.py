#!/usr/bin/env python3
from __future__ import annotations

"""
Compatibility entrypoint for the main VulnScope launcher.

`vulnscope_clean_cli.py` runs the tool setup gate first, then imports this
module to start the existing authorized autonomous workflow. Keeping this file
separate prevents `main.py` from failing when the clean launcher expects
`kai_flow_core` to exist.
"""

from kai_safe_interface import main as _kai_main


def main() -> int:
    return int(_kai_main())


if __name__ == "__main__":
    raise SystemExit(main())
