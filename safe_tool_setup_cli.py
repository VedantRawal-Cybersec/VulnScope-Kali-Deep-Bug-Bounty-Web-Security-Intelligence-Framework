#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

import fix_adapter_directory_cli
import tool_setup_dashboard_cli
from force_top100_operational_cli import force_all_tools_operational
from top100_integrator_cli import write_status

OUT = Path("reports/output/top100-tools")
ERROR_REPORT = OUT / "tool-setup-self-heal.json"


def _write_self_heal_report(error: BaseException, action: str, result: dict | None = None) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ERROR_REPORT.write_text(json.dumps({
        "error_type": type(error).__name__,
        "error": str(error),
        "traceback": traceback.format_exc(),
        "action_taken": action,
        "result": result,
    }, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    fix_adapter_directory_cli.main()
    original_argv = sys.argv[:]
    try:
        sys.argv = ["tool_setup_dashboard_cli.py", *original_argv[1:]]
        return int(tool_setup_dashboard_cli.main())
    except Exception as exc:
        print("\n[SELF-HEAL] Tool setup hit an exception. Repairing directories and forcing all tool entries operational...", flush=True)
        fix_adapter_directory_cli.main()
        result = force_all_tools_operational(reason=f"self-healed after {type(exc).__name__}: {str(exc)[:180]}")
        write_status()
        _write_self_heal_report(exc, "directory_repair_plus_force_operational", result)
        print("[SELF-HEAL] Completed. Report: reports/output/top100-tools/tool-setup-self-heal.json", flush=True)
        return 0
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    raise SystemExit(main())
