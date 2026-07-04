#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.tool_manager import LOGS_DIR, VULNSCOPE_LOG, ToolManager
from core.tool_registry import ToolRegistry

PHASE_ORDER = ["recon", "discovery", "validation", "exploitation", "reporting"]
MODE_RANK = {"passive": 0, "safe-active": 1, "lab": 2}


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
    """Runs enabled installed tools in phase order and records evidence.

    Status semantics:
    - skipped: selected and skipped due to missing runtime input.
    - not_ready: configured tool is missing approval or run command.
    - blocked_by_safety: mode/safety boundary blocked execution.
    - completed/failed/timed_out: actual execution result.
    """

    def __init__(self, *, registry: ToolRegistry | None = None, manager: ToolManager | None = None, dashboard: object | None = None, report_dir: Path | None = None, state: object | None = None, scan_mode: str = "passive") -> None:
        self.registry = registry or ToolRegistry()
        self.manager = manager or ToolManager(self.registry)
        self.manager.reconcile_installed_tools(approve_known=True, enable=True)
        self.dashboard = dashboard
        self.report_dir = report_dir or Path("reports/output/dynamic-tools")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.state = state
        self.scan_mode = scan_mode
        self.runs: list[ScheduledToolRun] = []

    def _log(self, message: str, *, level: str = "INFO", data: dict[str, Any] | None = None) -> None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "message": message, "data": data or {}}
        with VULNSCOPE_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

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
                parameters=parsed.query or "installed tool context",
                probe_string="registered-tool-command",
                evidence=f"tool_id={tool_id} status={status}",
                safety_status="registered installed tool • approval-gated • stdout/stderr captured",
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            level = "ERROR" if status in {"failed", "timed_out"} else "WARNING" if status in {"not_ready", "blocked_by_safety"} else "INFO"
            self.dashboard.event(level, message)

    @staticmethod
    def _severity_from_value(value: str) -> str:
        value = str(value or "info").lower()
        if value in {"critical", "high"}:
            return "MEDIUM"
        if value in {"medium"}:
            return "MEDIUM"
        if value in {"low"}:
            return "LOW"
        return "INFO"

    def _finding_from_observation(self, tool: Any, payload: dict[str, Any], target: str, output_path: str) -> dict[str, Any]:
        info = payload.get("info", {}) if isinstance(payload, dict) else {}
        title = info.get("name") or payload.get("template-id") or payload.get("host") or f"{tool.name} observation"
        severity = self._severity_from_value(info.get("severity") or payload.get("severity") or "info")
        affected = payload.get("matched-at") or payload.get("url") or payload.get("host") or target
        return {"id": "external_" + str(abs(hash(json.dumps(payload, sort_keys=True, default=str))))[:12], "title": f"{tool.name}: {title}", "status": "Manual Review Lead", "severity": severity, "confidence": 70, "category": "External Tool Observation", "affected_url": affected, "parameter": None, "evidence": json.dumps(payload, ensure_ascii=False, default=str)[:2000], "impact": "A registered external tool produced output that should be manually reviewed before reporting.", "recommendation": "Review the saved stdout/stderr and validate the observation in the authorized scope.", "safe_probe": tool.tool_id, "reproduction_steps": ["Run the same VulnScope scan with dynamic tools enabled.", f"Review dynamic tool output: {output_path}", "Manually validate impact before reporting."]}

    def _capture_findings(self, tool: Any, payload: dict[str, Any], target: str) -> int:
        if self.state is None or not hasattr(self.state, "add_finding"):
            return 0
        result = payload.get("result", {})
        output_path = result.get("stdout_path", "")
        parsed = payload.get("parsed_output")
        findings: list[dict[str, Any]] = []
        if isinstance(parsed, list):
            for row in parsed[:50]:
                if isinstance(row, dict) and row:
                    findings.append(self._finding_from_observation(tool, row, target, output_path))
        elif isinstance(parsed, dict):
            if isinstance(parsed.get("results"), list):
                for row in parsed["results"][:50]:
                    findings.append(self._finding_from_observation(tool, row if isinstance(row, dict) else {"raw": str(row)}, target, output_path))
            elif parsed.get("raw"):
                raw = str(parsed.get("raw") or "").strip()
                if raw:
                    findings.append(self._finding_from_observation(tool, {"raw": raw[:2000]}, target, output_path))
        count = 0
        for finding in findings:
            try:
                self.state.add_finding(finding)
                count += 1
            except Exception as exc:
                self._log("Failed to add dynamic tool finding", level="ERROR", data={"tool_id": tool.tool_id, "error": str(exc)[:500]})
        if count and hasattr(self.state, "save"):
            self.state.save()
        return count

    def _phase_health(self, phase: str) -> dict[str, Any]:
        items = self.registry.list(enabled_only=False, phase=phase)
        return {
            "phase": phase,
            "total_registered": len(items),
            "enabled": sum(1 for t in items if t.enabled),
            "approved_run": sum(1 for t in items if t.approved_for_run),
            "with_run_command": sum(1 for t in items if bool(t.run)),
            "ready": sum(1 for t in items if t.enabled and t.approved_for_run and bool(t.run)),
            "not_ready": [
                {"tool_id": t.tool_id, "name": t.name, "enabled": t.enabled, "approved_run": t.approved_for_run, "has_run": bool(t.run), "ai_status": t.metadata.get("ai_repair_status") or t.metadata.get("analysis_status")}
                for t in items
                if not (t.enabled and t.approved_for_run and bool(t.run))
            ][:100],
        }

    def run_phase(self, phase: str, *, target: str, confirm: bool = False, timeout: int = 300) -> list[ScheduledToolRun]:
        self.manager.reconcile_installed_tools(approve_known=True, enable=True)
        tools = self.registry.list(enabled_only=True, phase=phase)
        results: list[ScheduledToolRun] = []
        if not tools:
            self._log("No dynamic tools registered for phase", data={"phase": phase, "health": self._phase_health(phase)})
        for tool in tools:
            started = time.time()
            required_mode = "lab" if tool.phase == "exploitation" else "safe-active"
            if MODE_RANK.get(self.scan_mode, 0) < MODE_RANK.get(required_mode, 0):
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status="blocked_by_safety", started_at=started, finished_at=time.time(), elapsed_ms=0, error=f"requires {required_mode} mode")
                self.runs.append(run)
                results.append(run)
                self._dash(phase=phase, tool_id=tool.tool_id, status="blocked_by_safety", target=target, message=f"Blocked {tool.name}: requires {required_mode}")
                continue
            if not tool.approved_for_run or not tool.run:
                reason = "not approved_for_run" if not tool.approved_for_run else "no run command configured"
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status="not_ready", started_at=started, finished_at=time.time(), elapsed_ms=0, error=reason)
                self.runs.append(run)
                results.append(run)
                self._dash(phase=phase, tool_id=tool.tool_id, status="not_ready", target=target, message=f"Not ready {tool.name}: {reason}")
                self._log("Dynamic tool not ready", data={"tool_id": tool.tool_id, "reason": reason})
                continue
            self._dash(phase=phase, tool_id=tool.tool_id, status="running", target=target, message=f"Running dynamic tool {tool.name}")
            self._log("Starting dynamic tool", data={"tool_id": tool.tool_id, "name": tool.name, "phase": phase})
            try:
                payload = self.manager.run_tool(tool.tool_id, target=target, confirm=confirm, timeout=timeout)
                finding_count = self._capture_findings(tool, payload, target)
                status = str(payload.get("result", {}).get("status") or "completed")
                payload["findings_captured"] = finding_count
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status=status, started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), result=payload)
            except Exception as exc:
                run = ScheduledToolRun(tool_id=tool.tool_id, phase=phase, status="failed", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), error=str(exc)[:1000])
                self._log("Dynamic tool failed", level="ERROR", data={"tool_id": tool.tool_id, "error": str(exc)[:1000]})
            self._dash(phase=phase, tool_id=tool.tool_id, status=run.status, target=target, message=f"Dynamic tool {tool.name} finished with {run.status}")
            self.runs.append(run)
            results.append(run)
        self.write_summary()
        return results

    def _why_no_dynamic_findings(self) -> list[str]:
        reasons: list[str] = []
        if not self.runs:
            reasons.append("No dynamic tools were selected. Run `python3 vulnscope.py --ai-repair-tools` and then approve safe tools.")
            return reasons
        if not any(run.status in {"completed", "finding"} for run in self.runs):
            reasons.append("No dynamic tool completed successfully.")
        if any(run.status == "not_ready" for run in self.runs):
            reasons.append("Some tools are not ready: missing run approval or run command.")
        if any(run.status == "blocked_by_safety" for run in self.runs):
            reasons.append("Some tools were blocked by scan mode. Use safe-active/bugbounty for safe-active tools or lab only for lab tools.")
        if not any((run.result or {}).get("findings_captured") for run in self.runs):
            reasons.append("Dynamic tools produced no parsed observations. Check stdout/stderr paths in dynamic-tool-phase-summary.json.")
        return reasons

    def run_all(self, *, target: str, confirm: bool = False, timeout: int = 300) -> dict[str, Any]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        phase_health = {}
        for phase in PHASE_ORDER:
            phase_health[phase] = self._phase_health(phase)
            grouped[phase] = [asdict(item) for item in self.run_phase(phase, target=target, confirm=confirm, timeout=timeout)]
        return self.write_summary(extra={"target": target, "grouped": grouped, "phase_health": phase_health, "scan_mode": self.scan_mode, "why_no_dynamic_findings": self._why_no_dynamic_findings()})

    def write_summary(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"generated_at": time.time(), "phase_order": PHASE_ORDER, "runs": [asdict(item) for item in self.runs]}
        if extra:
            payload.update(extra)
        path = self.report_dir / "dynamic-tool-phase-summary.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["summary_path"] = str(path)
        return payload
