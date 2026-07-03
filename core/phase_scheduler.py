#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.tool_manager import ToolManager
from core.tool_registry import ToolRegistry

PHASE_ORDER = ["recon", "discovery", "validation", "exploitation", "reporting"]


@dataclass
class ScheduledToolRun:
    tool_id: str
    phase: str
    status: str
    started_at: float
    finished_at: float
    elapsed_ms: int
    error: str = ""
    result: dict[str, Any] = field(default_factory=dict)


class PhaseScheduler:
    """Runs enabled dynamic tools in phase order.

    Dynamic tools are optional and approval-gated. The scheduler never overrides
    the ToolManager safety gates; if a tool is disabled or not approved, it is
    recorded as skipped/failed by the manager path.
    """

    def __init__(self, *, registry: ToolRegistry | None = None, manager: ToolManager | None = None, dashboard: object | None = None, report_dir: Path | None = None) -> None:
        self.registry = registry or ToolRegistry()
        self.manager = manager or ToolManager(self.registry)
        self.dashboard = dashboard
        self.report_dir = report_dir or Path("reports/output/dynamic-tools")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.runs: list[ScheduledToolRun] = []

    def _dash(self, *, phase: str, tool_id: str, status: str, target: str, message: str) -> None:
        parsed = urlparse(target)
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(
                phase=f"Dynamic Tool: {phase}",
                current_agent="DynamicToolScheduler",
                current_tool=tool_id,
                decision=status,
                action=message,
                endpoint=target,
                request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
                path=parsed.path or "/",
                parameters=parsed.query or "dynamic tool context",
                probe_string="manifest-command",
                evidence=f"tool_id={tool_id} status={status}",
                safety_status="dynamic plugin scheduler • approval-gated • registry controlled",
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO" if status != "failed" else "ERROR", message)

    def run_phase(self, phase: str, *, target: str, confirm: bool = False, timeout: int = 300) -> list[ScheduledToolRun]:
        tools = self.registry.list(enabled_only=True, phase=phase)
        results: list[ScheduledToolRun] = []
        for tool in tools:
            started = time.time()
            self._dash(phase=phase, tool_id=tool.tool_id, status="running", target=target, message=f"Running dynamic tool {tool.name}")
            try:
                payload = self.manager.run_tool(tool.tool_id, target=target, confirm=confirm, timeout=timeout)
                status = str(payload.get("result", {}).get("status") or "completed")
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status=status, started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), result=payload)
            except Exception as exc:
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status="failed", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), error=str(exc)[:1000])
            self._dash(phase=phase, tool_id=tool.tool_id, status=run.status, target=target, message=f"Dynamic tool {tool.name} finished with {run.status}")
            self.runs.append(run)
            results.append(run)
        self.write_summary()
        return results

    def run_all(self, *, target: str, confirm: bool = False, timeout: int = 300) -> dict[str, Any]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for phase in PHASE_ORDER:
            grouped[phase] = [asdict(item) for item in self.run_phase(phase, target=target, confirm=confirm, timeout=timeout)]
        return self.write_summary(extra={"target": target, "grouped": grouped})

    def write_summary(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "generated_at": time.time(),
            "phase_order": PHASE_ORDER,
            "runs": [asdict(item) for item in self.runs],
        }
        if extra:
            payload.update(extra)
        path = self.report_dir / "dynamic-tool-phase-summary.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["summary_path"] = str(path)
        return payload
