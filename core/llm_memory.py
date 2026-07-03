#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.prompt_injection_guard import mask_secrets


@dataclass
class MemorySnapshot:
    target: str
    updated_at: float
    known_urls: list[str] = field(default_factory=list)
    known_paths: list[str] = field(default_factory=list)
    known_parameters: list[str] = field(default_factory=list)
    previous_reflections: int = 0
    failed_tools: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LLMMemory:
    """Evidence-only memory for LLM context.

    Secrets are masked. Raw response bodies, cookies, and authorization headers are not stored.
    """

    def __init__(self, target: str) -> None:
        self.target = normalize_target(target)
        self.out = cai_output_dir(self.target)
        self.out.mkdir(parents=True, exist_ok=True)
        self.scan_path = self.out / "scan-memory.json"
        self.target_path = self.out / "target-memory.json"
        self.tool_path = self.out / "tool-memory.json"

    def _load_json(self, path: Any, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    def update_from_state(self, state: Any) -> MemorySnapshot:
        urls = sorted([getattr(item, "url", "") for item in getattr(state, "urls", {}).values() if getattr(item, "url", "")])[:1000]
        paths = sorted({urlparse(url).path or "/" for url in urls})[:1000]
        params = sorted({getattr(item, "name", "") for item in getattr(state, "params", {}).values() if getattr(item, "name", "")})[:1000]
        failed_tools = sorted({str(test.test_name) for test in getattr(state, "tests", {}).values() if getattr(test, "status", "") == "failed"})[:200]
        reflections = sum(1 for finding in getattr(state, "findings", []) if "reflect" in str(finding.get("title", "")).lower())
        snapshot = MemorySnapshot(self.target, time.time(), urls, paths, params, reflections, failed_tools)
        write_json(self.scan_path, snapshot.to_dict())
        previous = self._load_json(self.target_path, {})
        merged = {
            "target": self.target,
            "updated_at": time.time(),
            "known_urls": sorted(set(previous.get("known_urls", [])) | set(urls))[:2000],
            "known_paths": sorted(set(previous.get("known_paths", [])) | set(paths))[:2000],
            "known_parameters": sorted(set(previous.get("known_parameters", [])) | set(params))[:2000],
            "previous_reflections": int(previous.get("previous_reflections", 0)) + reflections,
        }
        write_json(self.target_path, merged)
        write_json(self.tool_path, {"updated_at": time.time(), "failed_tools": failed_tools})
        return snapshot

    def llm_summary(self, limit: int = 60) -> dict[str, Any]:
        target_memory = self._load_json(self.target_path, {})
        return {
            "target": self.target,
            "known_paths": [mask_secrets(x)[0] for x in target_memory.get("known_paths", [])[:limit]],
            "known_parameters": [mask_secrets(x)[0] for x in target_memory.get("known_parameters", [])[:limit]],
            "previous_reflections": int(target_memory.get("previous_reflections", 0)),
            "redacted": True,
        }

    def write_reports(self) -> dict[str, str]:
        md_path = self.out / "llm-memory.md"
        summary = self.llm_summary(limit=120)
        lines = ["# VulnScope LLM Evidence Memory", "", f"Target: `{self.target}`", "", "## Known parameters"]
        for item in summary.get("known_parameters", [])[:120]:
            lines.append(f"- `{item}`")
        lines += ["", "## Known paths"]
        for item in summary.get("known_paths", [])[:120]:
            lines.append(f"- `{item}`")
        write_markdown(md_path, lines)
        return {"llm_scan_memory_json": str(self.scan_path), "llm_target_memory_json": str(self.target_path), "llm_tool_memory_json": str(self.tool_path), "llm_memory_md": str(md_path)}
