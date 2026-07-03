#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REGISTRY_PATH = Path("tools/registry.json")
VALID_PHASES = {"recon", "discovery", "validation", "exploitation", "reporting"}
VALID_PARSERS = {"json", "jsonl", "plain"}


@dataclass
class ToolArgument:
    name: str
    description: str = ""
    required: bool = False
    default: str = ""


@dataclass
class RegisteredTool:
    tool_id: str
    name: str
    version: str
    repo_url: str
    local_path: str
    phase: str
    install: list[list[str]] = field(default_factory=list)
    run: list[str] = field(default_factory=list)
    arguments: list[ToolArgument] = field(default_factory=list)
    output_parser: str = "plain"
    approved_for_install: bool = False
    approved_for_run: bool = False
    installed: bool = False
    enabled: bool = False
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["arguments"] = [asdict(arg) for arg in self.arguments]
        return payload

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> "RegisteredTool":
        args = [ToolArgument(**arg) for arg in payload.get("arguments", [])]
        payload = dict(payload)
        payload["arguments"] = args
        return RegisteredTool(**payload)


class ToolRegistry:
    """Persistent registry for dynamic tools installed under tools/."""

    def __init__(self, path: Path = REGISTRY_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tools: dict[str, RegisteredTool] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.tools = {}
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self.tools = {item["tool_id"]: RegisteredTool.from_dict(item) for item in payload.get("tools", [])}
        except Exception:
            self.tools = {}

    def save(self) -> None:
        payload = {"generated_at": time.time(), "tools": [tool.to_dict() for tool in sorted(self.tools.values(), key=lambda x: x.tool_id)]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def upsert(self, tool: RegisteredTool) -> RegisteredTool:
        tool.updated_at = time.time()
        self.tools[tool.tool_id] = tool
        self.save()
        return tool

    def get(self, tool_id: str) -> RegisteredTool | None:
        return self.tools.get(tool_id)

    def list(self, *, enabled_only: bool = False, phase: str | None = None) -> list[RegisteredTool]:
        items = list(self.tools.values())
        if enabled_only:
            items = [item for item in items if item.enabled]
        if phase:
            items = [item for item in items if item.phase == phase]
        return sorted(items, key=lambda item: (item.phase, item.name.lower()))

    def approve(self, tool_id: str, *, install: bool = False, run: bool = False, enable: bool = False) -> RegisteredTool:
        tool = self.tools[tool_id]
        if install:
            tool.approved_for_install = True
        if run:
            tool.approved_for_run = True
        if enable:
            tool.enabled = True
        tool.updated_at = time.time()
        self.save()
        return tool

    def set_installed(self, tool_id: str, installed: bool = True) -> None:
        tool = self.tools[tool_id]
        tool.installed = installed
        tool.updated_at = time.time()
        self.save()

    def as_table_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "id": tool.tool_id,
                "name": tool.name,
                "version": tool.version,
                "phase": tool.phase,
                "enabled": tool.enabled,
                "installed": tool.installed,
                "approved_install": tool.approved_for_install,
                "approved_run": tool.approved_for_run,
                "local_path": tool.local_path,
            }
            for tool in self.list()
        ]
