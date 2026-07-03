#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.tool_manager import ToolManager


def main() -> int:
    manager = ToolManager()
    payload = manager.diagnose_tools()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print("\nDiagnostics written to logs/tool_diagnostics.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
