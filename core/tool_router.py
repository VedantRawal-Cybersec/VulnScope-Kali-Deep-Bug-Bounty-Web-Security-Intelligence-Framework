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
    last_run_timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolRouter:
    """Selects eligible tools based on scan mode, available inputs, and safety."""

    def __init__(self, tools: list[RoutedTool] | None = None) -> None:
        self.tools = tools or self.default_tools()

    @staticmethod
    def default_tools() -> list[RoutedTool]:
        return [
            RoutedTool("crawler_v2", "Safe Crawler v2", "CrawlerAgent", "Discovery", "passive", "passive", ["target"]),
            RoutedTool("browser_crawler", "Transparent Browser Crawler", "CrawlerAgent", "Discovery", "passive", "passive", ["target"], False),
            RoutedTool("parameter_inventory", "Parameter Inventory", "ParameterDiscoveryAgent", "Discovery", "passive", "passive", ["urls"], False),
            RoutedTool("deep_asset_discovery", "Deep Public Asset Discovery", "AssetDiscoveryAgent", "Discovery", "passive", "passive", ["target"], False),
            RoutedTool("header_analyzer", "Header Analyzer", "HeaderAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("cookie_analyzer", "Cookie Analyzer", "CookieAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("metadata_checker", "robots/sitemap Metadata Checker", "ReconAgent", "Passive Analysis", "passive", "passive", ["target"], False),
            RoutedTool("js_route_review", "JavaScript Route Review", "JSExposureAgent", "Discovery", "passive", "passive", ["scripts"], False),
            RoutedTool("classification_review", "Parameter Classification Review", "FindingValidationAgent", "Validation", "passive", "passive", ["parameters"], False),
            RoutedTool("safe_canary_reflection", "Safe Canary Reflection Tester", "SafeCanaryTestingAgent", "Safe Active", "safe-active", "safe_active", ["safe_get_parameters"], True),
            RoutedTool("lab_mode_controller", "Lab Mode Controller", "LabModeController", "Lab Validation", "lab", "lab_only", ["target", "authorization"], False),
            RoutedTool("lab_parameter_review", "Lab Parameter Review", "LabModeController", "Lab Validation", "lab", "lab_only", ["parameters"], True),
            RoutedTool("external_tool_readiness", "External Tool Readiness Check", "LabModeController", "Lab Validation", "lab", "lab_only", ["target"], False),
            RoutedTool("report_generator", "Report Generator", "ReportAgent", "Reporting", "passive", "passive", ["state"], False),
            RoutedTool("llm_public_reasoning", "LLM Public Reasoning", "OllamaReasoningAgent", "Reasoning", "passive", "passive", ["state_summary"], False),
            RoutedTool("llm_evidence_validator", "LLM Evidence Validator", "FindingValidationAgent", "Validation", "passive", "passive", ["ambiguous_evidence"], False),
        ]

    def select(self, *, phase: str, scan_mode: str, available_inputs: set[str], limit: int = 10) -> list[RoutedTool]:
        selected: list[RoutedTool] = []
        for tool in self.tools:
            if phase and phase.lower() not in {tool.category.lower(), tool.agent_owner.lower(), tool.tool_id.lower(), "any"}:
                continue
            if MODE_RANK.get(scan_mode, 0) < MODE_RANK.get(tool.required_scan_mode, 0):
                tool.status = "blocked_by_safety"
                tool.reason = f"requires {tool.required_scan_mode} mode"
                continue
            missing = [item for item in tool.required_inputs if item not in available_inputs]
            if missing:
                tool.status = "skipped"
                tool.reason = "missing inputs: " + ", ".join(missing)
                continue
            clone = RoutedTool(**tool.to_dict())
            clone.status = "queued"
            clone.reason = "eligible"
            selected.append(clone)
            if len(selected) >= limit:
                break
        return selected

    def matrix(self) -> dict[str, Any]:
        counts = {status: 0 for status in STATUS_VALUES}
        for tool in self.tools:
            counts[tool.status if tool.status in counts else "queued"] += 1
        return {"total": len(self.tools), "counts": counts, "tools": [tool.to_dict() for tool in self.tools]}

    def mark(self, tool_id: str, status: str, reason: str = "") -> None:
        status = status if status in STATUS_VALUES else "failed"
        for tool in self.tools:
            if tool.tool_id == tool_id:
                tool.status = status
                tool.reason = reason
                tool.last_run_timestamp = time.time()
                return
