from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CATALOG_PATH = Path("arsenal/tool_catalog.yaml")


@dataclass
class ArsenalTool:
    name: str
    category: str
    binary: str
    install: dict[str, Any]
    risk_level: str
    requires_approval: bool
    enabled_by_default: bool
    safe_command_template: str
    output_file: str
    notes: str


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Tool catalog not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_tools(path: Path = CATALOG_PATH) -> list[ArsenalTool]:
    data = load_catalog(path)
    tools = []
    for item in data.get("tools", []):
        tools.append(
            ArsenalTool(
                name=str(item["name"]),
                category=str(item["category"]),
                binary=str(item["binary"]),
                install=dict(item.get("install", {})),
                risk_level=str(item.get("risk_level", "unknown")),
                requires_approval=bool(item.get("requires_approval", True)),
                enabled_by_default=bool(item.get("enabled_by_default", False)),
                safe_command_template=str(item.get("safe_command_template", "")),
                output_file=str(item.get("output_file", f"reports/output/arsenal/{item['name']}.txt")),
                notes=str(item.get("notes", "")),
            )
        )
    return tools


def load_profiles(path: Path = CATALOG_PATH) -> dict[str, Any]:
    return dict(load_catalog(path).get("profiles", {}))


def tools_for_profile(profile: str) -> list[ArsenalTool]:
    profiles = load_profiles()
    if profile not in profiles:
        raise ValueError(f"Unknown profile: {profile}. Available: {', '.join(profiles)}")
    categories = set(profiles[profile].get("categories", []))
    return [tool for tool in load_tools() if tool.category in categories]


def catalog_as_json() -> str:
    return json.dumps(load_catalog(), indent=2, ensure_ascii=False)
