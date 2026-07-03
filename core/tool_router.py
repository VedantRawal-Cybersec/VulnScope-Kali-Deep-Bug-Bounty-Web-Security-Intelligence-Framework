#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

STATUS_VALUES = {"queued", "running", "completed", "failed", "skipped", "blocked_by_scope", "blocked_by_safety", "timed_out"}
MODE_RANK = {"passive": 0, "safe-active": 1, "lab": 2}


@dataclass
class RoutedTool:
    tool_id: str
    tool_name: str
    agent_owner: str
    category: str
    required_scan_mode: str
    safety_level: str
    required_inputs: list[str] = field(default_factory=list)
    finding_capability: bool = False
    status: str = "queued"
    reason: str = ""
    output_count: int = 0
    error_message: str = ""
    run_count: int = 0
    last_run_timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolRouter:
    """Stateful router for eligible tools and real execution telemetry."""

    def __init__(self, tools: list[RoutedTool] | None = None) -> None:
        self.tools = tools or self.default_tools()

    @staticmethod
    def default_tools() -> list[RoutedTool]:
        return [
            RoutedTool("availability_checker", "Target Availability Checker", "ScopeAgent", "Scope", "passive", "passive", ["target"]),
            RoutedTool("header_analyzer", "Header Analyzer", "HeaderAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("cookie_analyzer", "Cookie Analyzer", "CookieAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("metadata_checker", "robots/sitemap Metadata Checker", "ReconAgent", "Passive Analysis", "passive", "passive", ["target"], False),
            RoutedTool("crawler_v2", "Safe Crawler v2", "CrawlerAgent", "Discovery", "passive", "passive", ["target"]),
            RoutedTool("browser_crawler", "Transparent Browser Crawler", "CrawlerAgent", "Discovery", "passive", "passive", ["target"], False),
            RoutedTool("js_route_review", "JavaScript Route Review", "JSExposureAgent", "Discovery", "passive", "passive", ["scripts"], False),
            RoutedTool("parameter_inventory", "Parameter Inventory", "ParameterDiscoveryAgent", "Discovery", "passive", "passive", ["urls"], False),
            RoutedTool("test_queue_builder", "Test Queue Builder", "TestPlanningAgent", "Planning", "passive", "passive", ["parameters"], False),
            RoutedTool("classification_review", "Parameter Classification Review", "FindingValidationAgent", "Validation", "passive", "passive", ["parameters"], False),
            RoutedTool("safe_canary_reflection", "Safe Canary Reflection Tester", "SafeCanaryTestingAgent", "Safe Active", "safe-active", "safe_active", ["safe_get_parameters"], True),
            RoutedTool("llm_public_reasoning", "LLM Public Reasoning", "OllamaReasoningAgent", "Reasoning", "passive", "passive", ["state_summary"], False),
            RoutedTool("llm_evidence_validator", "LLM Evidence Validator", "FindingValidationAgent", "Validation", "passive", "passive", ["ambiguous_evidence"], False),
            RoutedTool("scan_quality_gate", "Scan Quality Gate", "RiskScoringAgent", "Quality", "passive", "passive", ["state"], False),
            RoutedTool("report_generator", "Report Generator", "ReportAgent", "Reporting", "passive", "passive", ["state"], False),
        ]

    def _find(self, tool_id: str) -> RoutedTool | None:
        for tool in self.tools:
            if tool.tool_id == tool_id:
                return tool
        return None

    def select(self, *, phase: str, scan_mode: str, available_inputs: set[str], limit: int = 10) -> list[RoutedTool]:
        selected: list[RoutedTool] = []
        for tool in self.tools:
            if phase and phase.lower() not in {tool.category.lower(), tool.agent_owner.lower(), tool.tool_id.lower(), "any"}:
                continue
            if MODE_RANK.get(scan_mode, 0) < MODE_RANK.get(tool.required_scan_mode, 0):
                self.mark(tool.tool_id, "blocked_by_safety", f"requires {tool.required_scan_mode} mode")
                continue
            missing = [item for item in tool.required_inputs if item not in available_inputs]
            if missing:
                self.mark(tool.tool_id, "skipped", "missing inputs: " + ", ".join(missing))
                continue
            clone = RoutedTool(**tool.to_dict())
            clone.status = "queued"
            clone.reason = "eligible"
            selected.append(clone)
            if len(selected) >= limit:
                break
        return selected

    def mark(self, tool_id: str, status: str, reason: str = "", *, output_count: int | None = None, error_message: str = "") -> None:
        status = status if status in STATUS_VALUES else "failed"
        tool = self._find(tool_id)
        if tool is None:
            return
        tool.status = status
        tool.reason = reason
        if output_count is not None:
            tool.output_count = int(output_count)
        if error_message:
            tool.error_message = error_message[:500]
        tool.last_run_timestamp = time.time()
        if status == "running":
            tool.run_count += 1

    def started(self, tool_id: str, reason: str = "") -> None:
        self.mark(tool_id, "running", reason)

    def completed(self, tool_id: str, *, output_count: int = 0, reason: str = "completed") -> None:
        self.mark(tool_id, "completed", reason, output_count=output_count)

    def failed(self, tool_id: str, error: str) -> None:
        self.mark(tool_id, "failed", "failed", error_message=error)

    def blocked(self, tool_id: str, reason: str) -> None:
        self.mark(tool_id, "blocked_by_safety", reason)

    def skipped(self, tool_id: str, reason: str) -> None:
        self.mark(tool_id, "skipped", reason)

    def matrix(self) -> dict[str, Any]:
        counts = {status: 0 for status in STATUS_VALUES}
        for tool in self.tools:
            counts[tool.status if tool.status in counts else "queued"] += 1
        return {
            "total": len(self.tools),
            "counts": counts,
            "completed_tools": [tool.tool_id for tool in self.tools if tool.status == "completed"],
            "blocked_tools": [tool.tool_id for tool in self.tools if tool.status.startswith("blocked")],
            "tools": [tool.to_dict() for tool in self.tools],
        }
