#!/usr/bin/env python3
from __future__ import annotations

import time
from typing import Any

from core.live_dashboard import LiveDashboard as BaseLiveDashboard, SPINNER


class LiveDashboard(BaseLiveDashboard):
    """Dashboard wrapper that tracks actual module lifecycle rows."""

    TOOL_ORDER_V2 = [
        "technology_intelligence",
        "api_discovery",
        "access_matrix",
        "security_scorecard",
        "final_report_index",
        "crawler_v2",
        "browser_crawler",
        "parameter_inventory",
        "header_analyzer",
        "cookie_analyzer",
        "metadata_checker",
        "js_route_review",
        "classification_review",
        "safe_canary_reflection",
        "deep_scan_phase_pack",
        "external_tool_readiness",
        "unified_research_orchestrator",
        "report_generator",
        "llm_public_reasoning",
        "safe_surface_engine",
        "deepseek_react_loop",
    ]

    TOOL_ALIASES_V2 = {
        "initializer": [],
        "bootstrap": ["llm_public_reasoning"],
        "scope_guard": ["llm_public_reasoning"],
        "availability_checker": ["metadata_checker"],
        "technology_intelligence": ["technology_intelligence"],
        "TechnologyIntelAgent": ["technology_intelligence"],
        "api_discovery": ["api_discovery"],
        "APIDiscoveryAgent": ["api_discovery"],
        "access_matrix": ["access_matrix"],
        "AccessMatrixAgent": ["access_matrix"],
        "security_scorecard": ["security_scorecard"],
        "final_report_index": ["final_report_index"],
        "passive_analyzers": ["header_analyzer", "cookie_analyzer"],
        "header_analyzer": ["header_analyzer"],
        "cookie_analyzer": ["cookie_analyzer"],
        "metadata_checker": ["metadata_checker"],
        "safe_crawler": ["crawler_v2"],
        "crawler_v2": ["crawler_v2"],
        "browser_crawler": ["browser_crawler"],
        "parameter_inventory": ["parameter_inventory"],
        "review_scripts": ["js_route_review"],
        "js_route_review": ["js_route_review"],
        "deep_scan_phase_pack": ["deep_scan_phase_pack"],
        "dynamic_tool_scheduler": ["external_tool_readiness"],
        "unified_research_orchestrator": ["unified_research_orchestrator"],
        "llm_gateway.health_check": ["llm_public_reasoning"],
        "llm_gateway.plan_actions": ["llm_public_reasoning"],
        "llm_public_reasoning": ["llm_public_reasoning"],
        "cai_react_planner": ["safe_canary_reflection", "classification_review"],
        "deepseek_react_loop": ["deepseek_react_loop"],
        "reflection_canary": ["safe_canary_reflection"],
        "redirect_review": ["safe_canary_reflection"],
        "test_parameter": ["safe_canary_reflection"],
        "safe_surface_engine": ["safe_surface_engine", "parameter_inventory"],
        "surface_map": ["safe_surface_engine", "parameter_inventory"],
        "report_generator": ["report_generator"],
    }

    LABELS = {"running": "running", "completed": "completed", "failed": "failed", "timed_out": "timed out", "blocked": "blocked", "blocked_by_safety": "blocked", "blocked_by_scope": "blocked", "skipped": "skipped", "not_ready": "needs config", "inactive": "inactive", "queued": "queued"}
    TERMINAL = {"completed", "failed", "timed_out", "blocked", "blocked_by_safety", "blocked_by_scope", "skipped", "not_ready", "inactive"}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.tool_statuses_v2: dict[str, str] = {tool: "inactive" for tool in self.TOOL_ORDER_V2}
        self.last_active_tools_v2: list[str] = []

    def _ids_for_tool_v2(self, raw: Any) -> list[str]:
        raw_text = str(raw or "").strip()
        if not raw_text:
            return []
        if raw_text.startswith("dynamic:"):
            return [raw_text]
        return [item for item in self.TOOL_ALIASES_V2.get(raw_text, [raw_text]) if item]

    def _status_v2(self, kwargs: dict[str, Any]) -> str:
        raw = str(kwargs.get("tool_status") or kwargs.get("status") or kwargs.get("decision") or "running").lower()
        if "completed" in raw or raw in {"done", "success"}:
            return "completed"
        if "timeout" in raw:
            return "timed_out"
        if "failed" in raw or "error" in raw:
            return "failed"
        if "blocked" in raw:
            return "blocked"
        if "skip" in raw:
            return "skipped"
        if "not_ready" in raw or "needs" in raw or "config" in raw:
            return "not_ready"
        if "inactive" in raw:
            return "inactive"
        if "queued" in raw:
            return "queued"
        return "running"

    def _touch_tools_v2(self, kwargs: dict[str, Any]) -> None:
        explicit = kwargs.get("tool_statuses")
        if isinstance(explicit, dict):
            for key, value in explicit.items():
                self.tool_statuses_v2[str(key)] = self._status_v2({"status": value})
        current = kwargs.get("current_tool")
        if current is None:
            return
        ids = self._ids_for_tool_v2(current)
        if not ids:
            return
        status = self._status_v2(kwargs)
        for old in self.last_active_tools_v2:
            if old not in ids and self.tool_statuses_v2.get(old) in {"running", "queued"}:
                self.tool_statuses_v2[old] = "completed"
        for tool_id in ids:
            if self.tool_statuses_v2.get(tool_id) in self.TERMINAL and status == "running":
                continue
            self.tool_statuses_v2[tool_id] = status
        self.last_active_tools_v2 = [] if status in self.TERMINAL else ids

    def update(self, **kwargs: Any) -> None:
        self._touch_tools_v2(kwargs)
        super().update(**kwargs)

    def _finalize_v2(self) -> None:
        for tool_id in list(self.last_active_tools_v2):
            if self.tool_statuses_v2.get(tool_id) == "running":
                self.tool_statuses_v2[tool_id] = "completed"
        self.last_active_tools_v2 = []
        for tool_id, status in list(self.tool_statuses_v2.items()):
            if status == "queued":
                self.tool_statuses_v2[tool_id] = "inactive"

    def _counts_v2(self) -> dict[str, int]:
        values = list(self.tool_statuses_v2.values())
        return {"total": len(values), "running": values.count("running"), "completed": values.count("completed"), "failed": values.count("failed") + values.count("timed_out"), "blocked": values.count("blocked") + values.count("blocked_by_safety") + values.count("blocked_by_scope"), "skipped": values.count("skipped"), "inactive": values.count("inactive"), "not_ready": values.count("not_ready")}

    def _tool_rows(self, snap: Any) -> list[str]:
        counts = self._counts_v2()
        rows = [f"Total: {counts['total']:<3} Running: {counts['running']:<2} Completed: {counts['completed']:<3} Failed: {counts['failed']:<2} Blocked: {counts['blocked']:<2} Skip: {counts['skipped']:<2}", f"Inactive: {counts['inactive']:<3} Needs Config: {counts['not_ready']:<3}   (inactive = not needed in this run)", "─" * 76]
        order = list(self.TOOL_ORDER_V2)
        for key in sorted(self.tool_statuses_v2):
            if key not in order and self.tool_statuses_v2.get(key) != "inactive":
                order.append(key)
        for tool in order:
            status = self.tool_statuses_v2.get(tool, "inactive")
            label = self.LABELS.get(status, status)
            if status == "running":
                label = f"{SPINNER[snap.spinner_index]} running"
            elif status == "completed":
                label = "✓ completed"
            elif status == "inactive":
                label = "— inactive"
            elif status == "not_ready":
                label = "⚙ needs config"
            elif status in {"failed", "timed_out"}:
                label = "✗ " + label
            elif status in {"blocked", "blocked_by_safety", "blocked_by_scope"}:
                label = "■ blocked"
            elif status == "skipped":
                label = "↷ skipped"
            else:
                label = "◻ " + label
            rows.append(f"► {tool:<30} {label}")
        return rows[:26]

    def write_reports(self, out_dir: Any) -> dict[str, str]:
        self._finalize_v2()
        reports = super().write_reports(out_dir)
        try:
            from pathlib import Path
            import json
            out = Path(out_dir)
            path = out / "tool-status-dashboard.json"
            path.write_text(json.dumps({"tool_statuses": self.tool_statuses_v2, "counts": self._counts_v2(), "generated_at": time.time()}, indent=2, ensure_ascii=False), encoding="utf-8")
            reports["tool_status_dashboard_json"] = str(path)
        except Exception:
            pass
        return reports
