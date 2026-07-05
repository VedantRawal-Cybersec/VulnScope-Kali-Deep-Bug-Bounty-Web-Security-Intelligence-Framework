#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from core.tool_registry import ToolRegistry


STATUS_VALUES = {"queued", "running", "completed", "failed", "skipped", "blocked_by_scope", "blocked_by_safety", "timed_out", "inactive", "not_ready"}
ACTIVE_STATUSES = {"queued", "running", "completed", "failed", "timed_out"}
MODE_RANK = {"passive": 0, "safe-active": 1, "lab": 2}
PHASE_CATEGORY = {
    "recon": "Reconnaissance",
    "discovery": "Discovery",
    "validation": "Validation",
    "exploitation": "Lab Validation",
    "reporting": "Reporting",
}


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
    """Dashboard-facing tool router.

    Registry entries that are installed but not approved/configured are intentionally
    kept out of the live tool matrix. They still appear in --list-tools and repair
    diagnostics, but they no longer make the dashboard look broken.
    """

    def __init__(self, tools: list[RoutedTool] | None = None, *, load_dynamic: bool = True) -> None:
        self.tools = tools or self.default_tools()
        self.unready_dynamic_count = 0
        if load_dynamic:
            dynamic, unready = self.dynamic_tools()
            self.tools.extend(dynamic)
            self.unready_dynamic_count = unready

    @staticmethod
    def default_tools() -> list[RoutedTool]:
        return [
            RoutedTool("crawler_v2", "Safe Crawler v2", "CrawlerAgent", "Discovery", "passive", "passive", ["target"]),
            RoutedTool("browser_crawler", "Transparent Browser Crawler", "CrawlerAgent", "Discovery", "passive", "passive", ["target"], False),
            RoutedTool("parameter_inventory", "Parameter Inventory", "ParameterDiscoveryAgent", "Discovery", "passive", "passive", ["urls"], False),
            RoutedTool("deep_asset_discovery", "Deep Public Asset Discovery", "AssetDiscoveryAgent", "Discovery", "passive", "passive", ["target"], False),
            RoutedTool("deep_scan_phase_pack", "Deep Scan Phase Pack", "DeepScanPhasePack", "Discovery", "passive", "safe_active_enrichment", ["state"], False),
            RoutedTool("unified_research_orchestrator", "Unified Research Orchestrator", "UnifiedResearchOrchestrator", "Reasoning", "passive", "decision_layer", ["state"], False),
            RoutedTool("header_analyzer", "Header Analyzer", "HeaderAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("cookie_analyzer", "Cookie Analyzer", "CookieAnalysisAgent", "Passive Analysis", "passive", "passive", ["root_response"], False),
            RoutedTool("metadata_checker", "robots/sitemap Metadata Checker", "ReconAgent", "Passive Analysis", "passive", "passive", ["target"], False),
            RoutedTool("js_route_review", "JavaScript Route Review", "JSExposureAgent", "Discovery", "passive", "passive", ["scripts"], False),
            RoutedTool("classification_review", "Parameter Classification Review", "FindingValidationAgent", "Validation", "passive", "passive", ["parameters"], False),
            RoutedTool("safe_canary_reflection", "Safe Canary Reflection Tester", "SafeCanaryTestingAgent", "Safe Active", "safe-active", "safe_active", ["safe_get_parameters"], True),
            RoutedTool("external_tool_readiness", "External Tool Readiness Check", "DynamicToolScheduler", "Dynamic Tools", "safe-active", "approval_gated_installed_tool", ["target"], False),
            RoutedTool("report_generator", "Report Generator", "ReportAgent", "Reporting", "passive", "passive", ["state"], False),
            RoutedTool("llm_public_reasoning", "LLM Public Reasoning", "OllamaReasoningAgent", "Reasoning", "passive", "passive", ["state_summary"], False),
        ]

    @staticmethod
    def dynamic_tools() -> tuple[list[RoutedTool], int]:
        try:
            from core.tool_manager import ToolManager
            manager = ToolManager()
            manager.reconcile_installed_tools(approve_known=True, enable=True)
            registry = manager.registry
        except Exception:
            registry = ToolRegistry()
        routed: list[RoutedTool] = []
        unready = 0
        for tool in registry.list(enabled_only=False):
            has_command = bool(tool.run)
            ready = bool(tool.enabled and tool.approved_for_run and has_command)
            if not ready:
                unready += 1
                continue
            routed.append(
                RoutedTool(
                    tool_id="dynamic:" + tool.tool_id,
                    tool_name=tool.name,
                    agent_owner="DynamicToolScheduler",
                    category=PHASE_CATEGORY.get(tool.phase, "Discovery"),
                    required_scan_mode="lab" if tool.phase == "exploitation" else "safe-active",
                    safety_level="approval_gated_installed_tool",
                    required_inputs=["target"],
                    finding_capability=True,
                    status="queued",
                    reason="ready",
                )
            )
        return routed, unready

    def select(self, *, phase: str, scan_mode: str, available_inputs: set[str], limit: int = 10) -> list[RoutedTool]:
        selected: list[RoutedTool] = []
        for tool in self.tools:
            if phase and phase.lower() not in {tool.category.lower(), tool.agent_owner.lower(), tool.tool_id.lower(), "any"}:
                if tool.status == "queued":
                    tool.status = "inactive"
                    tool.reason = f"not in phase {phase}"
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
        active_total = sum(counts.get(status, 0) for status in ACTIVE_STATUSES)
        unavailable_total = counts.get("inactive", 0) + counts.get("not_ready", 0) + self.unready_dynamic_count
        return {"total": len(self.tools), "active_total": active_total, "unavailable_total": unavailable_total, "unready_dynamic_hidden": self.unready_dynamic_count, "counts": counts, "tools": [tool.to_dict() for tool in self.tools]}

    def mark(self, tool_id: str, status: str, reason: str = "") -> None:
        status = status if status in STATUS_VALUES else "failed"
        for tool in self.tools:
            if tool.tool_id == tool_id or tool.tool_id == "dynamic:" + tool_id:
                tool.status = status
                tool.reason = reason
                tool.last_run_timestamp = time.time()
                return
