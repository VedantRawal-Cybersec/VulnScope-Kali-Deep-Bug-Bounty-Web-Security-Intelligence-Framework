from __future__ import annotations

import json
import shutil
from pathlib import Path

SUPPORTED_TOOLS = ["nuclei", "katana", "httpx", "ffuf", "dalfox", "zap-baseline.py", "sqlmap"]


def scan_environment() -> dict[str, object]:
    """Return safe local environment metadata for the AutoPilot engine."""
    tools = []
    for tool in SUPPORTED_TOOLS:
        tools.append(
            {
                "tool": tool,
                "installed": shutil.which(tool) is not None,
                "path": shutil.which(tool),
                "activation": "review_required" if shutil.which(tool) else "not_installed",
            }
        )
    return {
        "engine": "VulnScope AutoPilot Environment Scanner",
        "mode": "check_only",
        "supported_tools": tools,
        "safety": {
            "unknown_tools_disabled": True,
            "manual_approval_required": True,
            "auto_execute_unknown_code": False,
        },
    }


def write_environment_report(output_path: str = "reports/output/autopilot-environment.json") -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scan_environment(), indent=2), encoding="utf-8")


if __name__ == "__main__":
    write_environment_report()
    print("AutoPilot environment report written to reports/output/autopilot-environment.json")
