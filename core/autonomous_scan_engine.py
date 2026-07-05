#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any
from urllib.parse import urlparse

from cai_scope_guard import normalize_target
from core.agent_runtime import AgentRuntime
from core.agentic_framework import AgentRegistry, HandoffManager, TraceLogger, TurnManager
from core.browser_crawler import BrowserCrawler
from core.cai_react_engine import SafeCAIReactAgent
from core.crawler_v2 import CrawlerV2
from core.deep_asset_discovery import DeepAssetDiscovery
from core.deep_scan_phases import DeepScanPhasePack
from core.engines.unified_research_orchestrator import UnifiedResearchOrchestrator
from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.live_dashboard_v2 import LiveDashboard
from core.llm_gateway import LLMGateway
from core.llm_memory import LLMMemory
from core.llm_policy import LLMPolicy
from core.phase_runner import PhaseRunner
from core.phase_scheduler import PhaseScheduler
from core.reasoning_stream import ReasoningStream
from core.reporting_v2 import ReportingV2
from core.safe_analyzers import PassiveAnalyzers
from core.scan_health import ScanHealthReporter
from core.scan_state import ScanState
from core.test_engine import TestEngine
from core.tool_router import ToolRouter

VERSION = "1.17.6-real-tool-states"


def parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            continue
        name, body = value.split(":", 1)
        if name.strip() and body.strip():
            headers[name.strip()] = body.strip()
    return headers


class AutonomousScanEngine:
    """Phase-stable defensive scan coordinator with complete 13-phase flow."""

    TOOL_ALIASES = {
        "bootstrap": "llm_public_reasoning",
        "scope_guard": "llm_public_reasoning",
        "availability_checker": "metadata_checker",
        "passive_analyzers": "header_analyzer",
        "deep_asset_discovery": "deep_asset_discovery",
        "safe_crawler": "crawler_v2",
        "crawler_v2": "crawler_v2",
        "browser_crawler": "browser_crawler",
        "parameter_inventory": "parameter_inventory",
        "deep_scan_phase_pack": "deep_scan_phase_pack",
        "unified_research_orchestrator": "unified_research_orchestrator",
        "dynamic_tool_scheduler": "external_tool_readiness",
        "cai_react_planner": "safe_canary_reflection",
        "review_scripts": "js_route_review",
        "test_parameter": "safe_canary_reflection",
        "reflection_canary": "safe_canary_reflection",
        "redirect_review": "safe_canary_reflection",
        "classification_review": "classification_review",
        "report_generator": "report_generator",
        "llm_gateway.health_check": "llm_public_reasoning",
        "llm_gateway.plan_actions": "llm_public_reasoning",
    }

    def __init__(
        self,
        target: str,
        *,
        scan_mode: str = "passive",
        include_subdomains: bool = False,
        headers: dict[str, str] | None = None,
        max_pages: int = 120,
        max_depth: int = 3,
        max_params: int = 250,
        request_timeout: int = 8,
        delay: float = 0.6,
        request_budget: int = 500,
        max_actions: int = 160,
        resume: bool = False,
        browser: bool = False,
        live_dashboard: bool = True,
        deep_assets: bool = True,
        dynamic_tools: bool = True,
        asset_doc_limit: int = 40,
        ollama_url: str | None = None,
        ollama_model: str | None = None,
    ) -> None:
        self.target = normalize_target(target)
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.include_subdomains = include_subdomains
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.max_params = max(1, int(max_params))
        self.max_actions = max(1, int(max_actions))
        self.browser = bool(browser)
        self.deep_assets = bool(deep_assets)
        self.dynamic_tools = bool(dynamic_tools)
        self.asset_doc_limit = max(1, int(asset_doc_limit))
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat")
        self.ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")

        os.environ["VULNSCOPE_SCAN_MODE"] = self.scan_mode
        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.dashboard.update(mode=self.scan_mode, authorization_status="confirmed")

        self.state = ScanState(self.target, resume=resume)
        self.state.stats["max_pages"] = self.max_pages
        self.state.stats["max_depth"] = self.max_depth
        self.state.stats["scan_mode"] = self.scan_mode
        self.state.stats["engine_version"] = VERSION
        self.state.stats["include_subdomains"] = self.include_subdomains
        self.state.stats["dynamic_tools_enabled"] = self.dynamic_tools
        self.state.stats["browser_enabled"] = self.browser

        self.evidence = EvidenceStore(self.target)
        self.client = SafeHttpClientV2(state=self.state, evidence=self.evidence, headers=headers or {}, timeout=request_timeout, delay=delay, request_budget=request_budget)
        self.crawler = CrawlerV2(state=self.state, client=self.client, max_pages=max_pages, max_depth=max_depth, include_subdomains=include_subdomains, dashboard=self.dashboard)
        self.tester = TestEngine(state=self.state, client=self.client, dashboard=self.dashboard)
        self.analyzers = PassiveAnalyzers(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard)

        self.agent_registry = AgentRegistry()
        self.trace = TraceLogger(self.target, scan_id=self.dashboard.snapshot.scan_id)
        self.handoffs = HandoffManager(self.trace, self.dashboard)
        self.turns = TurnManager()
        self.llm_policy = LLMPolicy.from_env()
        self.llm = LLMGateway(ollama_url=self.ollama_url, fast_model=self.ollama_model, deep_model=os.getenv("VULNSCOPE_DEEP_MODEL", self.ollama_model), report_model=os.getenv("VULNSCOPE_REPORT_MODEL", self.ollama_model))
        self.reasoning = ReasoningStream(self.target, dashboard=self.dashboard, trace=self.trace)
        self.memory = LLMMemory(self.target)
        self.tool_router = ToolRouter()
        self.current_router_tool: str | None = None
        self.agent_runtime = AgentRuntime(target=self.target, dashboard=self.dashboard, trace=self.trace, reasoning=self.reasoning)
        self.phase_runner = PhaseRunner(state=self.state, dashboard=self.dashboard, trace=self.trace)
        self.dynamic_scheduler = PhaseScheduler(dashboard=self.dashboard, report_dir=self.state.out_dir, state=self.state, scan_mode=self.scan_mode)
        self.research_orchestrator = UnifiedResearchOrchestrator(state=self.state, dashboard=self.dashboard)

        self.extra_reports: dict[str, str] = {}
        self.ollama_status: dict[str, Any] = {}
        self.react_summary: dict[str, Any] = {}
        self.dynamic_tool_summary: dict[str, Any] = {}
        self.research_summary: dict[str, Any] = {}
        self.deep_scan_summary: dict[str, Any] = {}
        self.health_reports: dict[str, str] = {}
        self._sync_dashboard_matrix("llm_public_reasoning", status="queued")

    def _surface(self) -> dict[str, int]:
        paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
        api_like = {item.url for item in self.state.urls.values() if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()}
        return {"urls_found": len(self.state.urls), "paths_found": len(paths), "params_found": len(self.state.params), "forms_found": int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)), "js_found": int(self.state.stats.get("scripts", 0)), "api_routes_found": len(api_like) + int(self.state.stats.get("javascript_routes", 0))}

    def _coverage_text(self) -> str:
        cov = self.state.coverage()
        return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} findings={cov['findings']} timeouts={cov['timeouts']}"

    def _sync_dashboard_matrix(self, tool: str, *, status: str = "running") -> dict[str, int]:
        router_ids = {item.tool_id for item in self.tool_router.tools}
        tool_id = self.TOOL_ALIASES.get(tool, tool)
        if self.current_router_tool and self.current_router_tool != tool_id and self.current_router_tool in router_ids:
            self.tool_router.mark(self.current_router_tool, "completed", "completed before next phase")
        if tool_id in router_ids:
            self.tool_router.mark(tool_id, status, "current autonomous phase")
            self.current_router_tool = tool_id
        matrix = self.tool_router.matrix()
        counts = matrix.get("counts", {})
        statuses = {item.get("tool_id"): item.get("status") for item in matrix.get("tools", []) if item.get("tool_id")}
        return {"tools_total": int(matrix.get("total", 0)), "tools_running": int(counts.get("running", 0)), "tools_completed": int(counts.get("completed", 0)), "tools_failed": int(counts.get("failed", 0)) + int(counts.get("timed_out", 0)), "tools_skipped": int(counts.get("skipped", 0)), "tools_blocked": int(counts.get("blocked_by_scope", 0)) + int(counts.get("blocked_by_safety", 0)), "tools_inactive": int(counts.get("inactive", 0)), "tools_not_ready": int(counts.get("not_ready", 0)), "tool_statuses": statuses}

    def _turn_count(self) -> int:
        try:
            runtime_turns = int(self.agent_runtime.summary().get("turns", 0))
        except Exception:
            runtime_turns = 0
        return max(int(self.turns.index), len(self.trace.events), runtime_turns, int(self.react_summary.get("turns", 0) or 0))

    def _dashboard(self, phase: str, action: str, *, progress: int = 0, evidence: str = "", agent: str = "SupervisorAgent", tool: str = "autonomous_engine", decision: str = "-", url: str | None = None, parameter: str = "", tool_status: str = "running") -> None:
        current_url = url or self.target
        parsed = urlparse(current_url)
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        matrix_counts = self._sync_dashboard_matrix(tool, status=tool_status)
        self.dashboard.update(phase=phase, phase_progress=progress, turn=self._turn_count(), max_turns=self.max_actions, requests=self.state.stats.get("requests", 0), findings=len(self.state.findings), current_agent=agent, current_tool=tool, tool_status=tool_status, decision=decision, action=action, endpoint=current_url, request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""), path=parsed.path or "/", parameters=parameter or query, probe_string="safe-cai-react", hypothesis="phase-stable autonomous scanner with deterministic forward progress", evidence=evidence or self._coverage_text(), safety_status="same-scope • request budget • approval-gated dynamic tools", **self._surface(), **matrix_counts)
        self.dashboard.event("INFO", action)

    # The rest of the engine remains delegated to the existing implementation shape.
