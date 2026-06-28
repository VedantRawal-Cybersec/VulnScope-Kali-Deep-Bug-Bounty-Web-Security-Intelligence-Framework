from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path

from arsenal.catalog import ArsenalTool, load_tools, tools_for_profile
from arsenal.installer import GO_BIN, is_installed


def run_healthcheck(profile: str | None = None) -> dict:
    tools = tools_for_profile(profile) if profile else load_tools()
    items = []
    for tool in tools:
        binary_path = shutil.which(tool.binary) or str(GO_BIN / tool.binary if (GO_BIN / tool.binary).exists() else "")
        items.append(
            {
                **asdict(tool),
                "installed": is_installed(tool),
                "binary_path": binary_path,
            }
        )
    result = {
        "profile": profile or "all",
        "tool_count": len(items),
        "installed_count": sum(1 for item in items if item["installed"]),
        "missing_count": sum(1 for item in items if not item["installed"]),
        "tools": items,
    }
    out = Path("reports/output/arsenal")
    out.mkdir(parents=True, exist_ok=True)
    (out / "healthcheck.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def print_healthcheck(result: dict) -> None:
    print("┌──────────────────── Auto Arsenal Healthcheck ────────────────────┐")
    print(f"Profile        : {result.get('profile')}")
    print(f"Tools          : {result.get('tool_count')}")
    print(f"Installed      : {result.get('installed_count')}")
    print(f"Missing        : {result.get('missing_count')}")
    print("└──────────────────────────────────────────────────────────────────┘")
    for item in result.get("tools", []):
        status = "OK" if item.get("installed") else "MISSING"
        print(f"[{status:<7}] {item.get('name'):<14} {item.get('category'):<22} {item.get('risk_level')}")
