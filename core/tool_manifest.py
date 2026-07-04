#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any


class ToolManifest:
    """Manifest loader for tools installed under ./tools.

    Supports the uploaded manifest.json format while remaining compatible with
    VulnScope's existing registry-based ToolManager.
    """

    REQUIRED_KEYS = ["name", "entry_point", "phase", "output_format", "safe_flags"]
    VALID_PHASES = {"recon", "discovery", "validation", "exploitation", "reporting"}
    VALID_OUTPUTS = {"json", "jsonl", "plain"}

    def __init__(self, tool_path: str | Path) -> None:
        self.tool_path = Path(tool_path)
        self.manifest_path = self.tool_path / "manifest.json"
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return self._generate_heuristic()
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return self._normalize(data)

    def _generate_heuristic(self) -> dict[str, Any]:
        name = self.tool_path.name
        lower = name.lower()
        phase = "discovery"
        if any(k in lower for k in ["subdomain", "subs", "osint", "recon", "httpx", "naabu"]):
            phase = "recon"
        elif any(k in lower for k in ["cve", "vuln", "scan", "nuclei"]):
            phase = "validation"
        elif any(k in lower for k in ["report", "evidence"]):
            phase = "reporting"
        entry = ""
        for candidate in ["main.py", "cli.py", "run.py", "scan.py", "scanner.py", "app.py", "run.sh", "setup.sh"]:
            if (self.tool_path / candidate).exists():
                entry = candidate
                break
        return self._normalize({
            "name": name,
            "entry_point": entry,
            "phase": phase,
            "output_format": "jsonl" if lower in {"nuclei", "katana", "httpx", "subfinder", "naabu"} else "plain",
            "safe_flags": [],
            "timeout": 240,
            "dependencies": [],
        })

    def _normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(data)
        normalized["name"] = str(normalized.get("name") or self.tool_path.name)
        phase = str(normalized.get("phase") or "discovery").lower()
        normalized["phase"] = phase if phase in self.VALID_PHASES else "discovery"
        output = str(normalized.get("output_format") or "plain").lower()
        normalized["output_format"] = output if output in self.VALID_OUTPUTS else "plain"
        normalized["entry_point"] = str(normalized.get("entry_point") or "")
        flags = normalized.get("safe_flags") or []
        if isinstance(flags, str):
            flags = shlex.split(flags)
        normalized["safe_flags"] = [str(item) for item in flags]
        normalized["timeout"] = int(normalized.get("timeout") or 240)
        dependencies = normalized.get("dependencies") or []
        if isinstance(dependencies, str):
            dependencies = [dependencies]
        normalized["dependencies"] = [str(item) for item in dependencies]
        return normalized

    def validate(self) -> bool:
        return all(key in self.data for key in self.REQUIRED_KEYS)

    def get_command(self, target: str, additional_flags: list[str] | None = None) -> list[str]:
        entry = str(self.data.get("entry_point") or "").strip()
        if not entry:
            return []
        if entry.endswith(".py"):
            cmd = ["python3", entry]
        elif entry.endswith(".sh"):
            cmd = ["bash", entry]
        else:
            cmd = shlex.split(entry)
        cmd.append(target)
        cmd.extend(self.data.get("safe_flags", []))
        if additional_flags:
            cmd.extend(additional_flags)
        return cmd

    def to_registry_manifest(self) -> dict[str, Any]:
        command = self.get_command("{target}")
        return {
            "name": self.data["name"],
            "version": str(self.data.get("version") or "unknown"),
            "phase": self.data["phase"],
            "install": self.data.get("dependencies", []),
            "run": command,
            "arguments": [{"name": "target", "description": "Target URL", "required": True}],
            "output_parser": self.data["output_format"],
            "metadata": {"manifest_json": True, "manifest_path": str(self.manifest_path)},
        }
