#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target


AGENT_NAMES = [
    "PlannerAgent",
    "ScopeAgent",
    "ReconAgent",
    "CrawlerAgent",
    "ParameterDiscoveryAgent",
    "HeaderAnalysisAgent",
    "CookieAnalysisAgent",
    "TLSAnalysisAgent",
    "CORSAnalysisAgent",
    "CSPAnalysisAgent",
    "JSExposureAgent",
    "SafeCanaryTestingAgent",
    "FindingValidationAgent",
    "RiskScoringAgent",
    "ReportAgent",
    "OllamaReasoningAgent",
    "SupervisorAgent",
]


@dataclass
class AgentSpec:
    agent_name: str
    role: str
    input_schema: dict[str, str]
    output_schema: dict[str, str]
    decision_boundary: str


@dataclass
class TraceEvent:
    scan_id: str
    timestamp: float
    turn_id: str
    agent_name: str
    tool_name: str
    phase: str
    status: str
    target_url: str = ""
    path: str = ""
    parameter: str = ""
    safe_probe_used: str = ""
    message: str = ""
    evidence_summary: str = ""
    progress_percent: int = 0


class TraceLogger:
    def __init__(self, target: str, *, scan_id: str) -> None:
        self.target = normalize_target(target)
        self.scan_id = scan_id
        self.out = cai_output_dir(self.target)
        self.path = self.out / "agent-trace.jsonl"
        self.events: list[TraceEvent] = []
        self.out.mkdir(parents=True, exist_ok=True)

    def log(self, *, agent_name: str, tool_name: str, phase: str, status: str, turn_id: str = "", target_url: str = "", path: str = "", parameter: str = "", safe_probe_used: str = "", message: str = "", evidence_summary: str = "", progress_percent: int = 0) -> TraceEvent:
        event = TraceEvent(
            scan_id=self.scan_id,
            timestamp=time.time(),
            turn_id=turn_id or "turn_" + uuid.uuid4().hex[:8],
            agent_name=agent_name,
            tool_name=tool_name,
            phase=phase,
            status=status,
            target_url=target_url,
            path=path,
            parameter=parameter,
            safe_probe_used=safe_probe_used,
            message=message,
            evidence_summary=evidence_summary,
            progress_percent=int(progress_percent),
        )
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        return event

    def write_reports(self, *_args: Any, **_kwargs: Any) -> dict[str, str]:
        """Write trace artifacts.

        Compatibility note: older/newer callers may pass an output path. TraceLogger
        already derives the correct target output directory, so optional arguments
        are accepted and ignored.
        """
        json_path = self.out / "agent-trace.json"
        md_path = self.out / "agent-trace.md"
        write_json(json_path, [asdict(event) for event in self.events])
        lines = ["# VulnScope Agent Trace", "", f"Target: `{self.target}`", f"Scan ID: `{self.scan_id}`", ""]
        for event in self.events[-300:]:
            lines.append(f"- `{event.turn_id}` `{event.agent_name}` phase=`{event.phase}` status=`{event.status}` tool=`{event.tool_name}` url=`{event.target_url}` param=`{event.parameter}` message={event.message}")
        write_markdown(md_path, lines)
        return {"agent_trace_jsonl": str(self.path), "agent_trace_json": str(json_path), "agent_trace_md": str(md_path)}


class AgentRegistry:
    def __init__(self) -> None:
        self.agents: dict[str, AgentSpec] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        roles = {
            "PlannerAgent": "Builds a safe turn-by-turn assessment plan and chooses the next action.",
            "ScopeAgent": "Validates target scope, authorization, schemes, and scan mode.",
            "ReconAgent": "Checks availability and imports passive target metadata.",
            "CrawlerAgent": "Discovers same-scope URLs, paths, forms, scripts, and route hints.",
            "ParameterDiscoveryAgent": "Builds the parameter inventory and safe-test queue.",
            "HeaderAnalysisAgent": "Evaluates response security headers using direct evidence.",
            "CookieAnalysisAgent": "Evaluates Set-Cookie hardening flags using direct evidence.",
            "TLSAnalysisAgent": "Records HTTPS/TLS posture and HTTPS enforcement observations.",
            "CORSAnalysisAgent": "Evaluates CORS response headers using direct evidence.",
            "CSPAnalysisAgent": "Evaluates CSP presence and weak directive observations.",
            "JSExposureAgent": "Extracts client-side route hints and safe exposure leads.",
            "SafeCanaryTestingAgent": "Runs harmless GET parameter canary comparisons.",
            "FindingValidationAgent": "Deduplicates and validates evidence before findings are marked confirmed.",
            "RiskScoringAgent": "Assigns severity and confidence based on evidence strength.",
            "ReportAgent": "Writes JSON, Markdown, CSV, trace, and evidence indexes.",
            "OllamaReasoningAgent": "Adds optional reasoning and prioritization with deterministic fallback.",
            "SupervisorAgent": "Controls the hierarchy, monitors failures, and keeps guardrails enforced.",
        }
        for name in AGENT_NAMES:
            self.agents[name] = AgentSpec(
                agent_name=name,
                role=roles[name],
                input_schema={"state": "current scan state", "events": "recent trace events"},
                output_schema={"decision": "safe next action", "handoff": "next agent or report stage"},
                decision_boundary="May only select registered safe actions and may not request destructive behavior.",
            )

    def names(self) -> list[str]:
        return list(self.agents)

    def write_reports(self, target: str) -> dict[str, str]:
        out = cai_output_dir(target)
        json_path = out / "agent-registry.json"
        md_path = out / "agent-registry.md"
        write_json(json_path, {key: asdict(value) for key, value in self.agents.items()})
        lines = ["# VulnScope Agent Registry", ""]
        for spec in self.agents.values():
            lines.append(f"- **{spec.agent_name}** — {spec.role}")
        write_markdown(md_path, lines)
        return {"agent_registry_json": str(json_path), "agent_registry_md": str(md_path)}


class HandoffManager:
    def __init__(self, trace: TraceLogger, dashboard: Any | None = None) -> None:
        self.trace = trace
        self.dashboard = dashboard

    def handoff(self, from_agent: str, to_agent: str, *, phase: str, message: str, target_url: str = "", path: str = "", parameter: str = "", progress_percent: int = 0) -> TraceEvent:
        event = self.trace.log(agent_name=from_agent, tool_name="handoff", phase=phase, status="handoff", target_url=target_url, path=path, parameter=parameter, message=f"{from_agent} → {to_agent}: {message}", progress_percent=progress_percent)
        if self.dashboard is not None:
            if hasattr(self.dashboard, "trace"):
                self.dashboard.trace(event.message)
            if hasattr(self.dashboard, "update"):
                self.dashboard.update(current_agent=to_agent, handoff=f"{from_agent} → {to_agent}", phase=phase, phase_progress=progress_percent, action=message)
            if hasattr(self.dashboard, "event"):
                self.dashboard.event("HANDOFF", event.message)
        return event


class TurnManager:
    def __init__(self) -> None:
        self.index = 0

    def next_turn(self) -> str:
        self.index += 1
        return f"turn_{self.index:04d}"
