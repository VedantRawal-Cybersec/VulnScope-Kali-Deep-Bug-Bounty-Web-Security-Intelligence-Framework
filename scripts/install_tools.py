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
    manager.reconcile_installed_tools(approve_known=True, enable=True)
    results = []
    ok = 0
    failed = 0
    for tool in manager.registry.list():
        try:
            run_results = manager.install_tool(tool.tool_id, confirm=True, timeout=900)
            success = all(item.status == "completed" for item in run_results) if run_results else True
            results.append({"tool_id": tool.tool_id, "name": tool.name, "ok": success, "results": [item.to_dict() for item in run_results]})
            ok += int(success)
            failed += int(not success)
        except Exception as exc:
            results.append({"tool_id": tool.tool_id, "name": tool.name, "ok": False, "error": str(exc)[:1000]})
            failed += 1
    payload = {"installed_successfully": ok, "failed": failed, "results": results, "log": "logs/tool_install.log"}
    Path("logs").mkdir(exist_ok=True)
    Path("logs/tool_install_summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
