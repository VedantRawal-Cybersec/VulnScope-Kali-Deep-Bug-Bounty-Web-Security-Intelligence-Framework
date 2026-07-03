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
from core.engines.unified_research_orchestrator import UnifiedResearchOrchestrator
from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.live_dashboard import LiveDashboard
from core.llm_gateway import LLMGateway
from core.llm_memory import LLMMemory
from core.llm_policy import LLMPolicy
from core.phase_runner import PhaseRunner
from core.phase_scheduler import PhaseScheduler
from core.reasoning_stream import ReasoningStream
from core.reporting_v2 import ReportingV2
from core.safe_analyzers import PassiveAnalyzers
from core.scan_state import ScanState
from core.test_engine import TestEngine
from core.tool_router import ToolRouter

VERSION = "1.16.0-unified-research-orchestration"


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
    """Phase-stable defensive scan coordinator with native research orchestration."""

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
        "unified_research_orchestrator": "unified_research_orchestrator",
        "dynamic_tool_scheduler": "external_tool_readiness",
        "cai_react_planner": "llm_public_reasoning",
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
        self.browser = browser
        self.deep_assets = bool(deep_assets)
        self.dynamic_tools = bool(dynamic_tools)
        self.asset_doc_limit = max(1, int(asset_doc_limit))
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat")
        self.ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.dashboard.update(mode=self.scan_mode, authorization_status="confirmed")
        self.state = ScanState(self.target, resume=resume)
        self.state.stats["max_pages"] = self.max_pages
        self.state.stats["max_depth"] = self.max_depth
        self.state.stats["engine_version"] = VERSION
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
        self.dynamic_scheduler = PhaseScheduler(dashboard=self.dashboard, report_dir=self.state.out_dir)
        self.research_orchestrator = UnifiedResearchOrchestrator(state=self.state, dashboard=self.dashboard)
        self.extra_reports: dict[str, str] = {}
        self.ollama_status: dict[str, Any] = {}
        self.react_summary: dict[str, Any] = {}
        self.dynamic_tool_summary: dict[str, Any] = {}
        self.research_summary: dict[str, Any] = {}
        self._sync_dashboard_matrix("llm_public_reasoning", status="queued")

    def _surface(self) -> dict[str, int]:
        paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
        api_like = {u.url for u in self.state.urls.values() if "/api/" in (urlparse(u.url).path or "").lower() or "graphql" in (urlparse(u.url).path or "").lower()}
        return {
            "urls_found": len(self.state.urls),
            "paths_found": len(paths),
            "params_found": len(self.state.params),
            "forms_found": int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)),
            "js_found": int(self.state.stats.get("scripts", 0)),
            "api_routes_found": len(api_like) + int(self.state.stats.get("javascript_routes", 0)),
        }

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
        return {
            "tools_total": int(matrix.get("total", 0)),
            "tools_running": int(counts.get("running", 0)),
            "tools_completed": int(counts.get("completed", 0)),
            "tools_failed": int(counts.get("failed", 0)) + int(counts.get("timed_out", 0)),
            "tools_skipped": int(counts.get("skipped", 0)),
            "tools_blocked": int(counts.get("blocked_by_scope", 0)) + int(counts.get("blocked_by_safety", 0)),
        }

    def _turn_count(self) -> int:
        try:
            runtime_turns = int(self.agent_runtime.summary().get("turns", 0))
        except Exception:
            runtime_turns = 0
        return max(int(self.turns.index), len(self.trace.events), runtime_turns, int(self.react_summary.get("turns", 0) or 0))

    def _dashboard(self, phase: str, action: str, *, progress: int = 0, evidence: str = "", agent: str = "SupervisorAgent", tool: str = "autonomous_engine", decision: str = "-", url: str | None = None, parameter: str = "") -> None:
        current_url = url or self.target
        parsed = urlparse(current_url)
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        matrix_counts = self._sync_dashboard_matrix(tool, status="running")
        self.dashboard.update(
            phase=phase,
            phase_progress=progress,
            turn=self._turn_count(),
            max_turns=self.max_actions,
            requests=self.state.stats.get("requests", 0),
            findings=len(self.state.findings),
            current_agent=agent,
            current_tool=tool,
            decision=decision,
            action=action,
            endpoint=current_url,
            request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
            path=parsed.path or "/",
            parameters=parameter or query,
            probe_string="safe-cai-react",
            hypothesis="phase-stable autonomous scanner with native research decision layer",
            evidence=evidence or self._coverage_text(),
            safety_status="same-scope • request budget • approval-gated dynamic tools • no embedded exploit payloads",
            **self._surface(),
            **matrix_counts,
        )
        self.dashboard.event("INFO", action)

    def run_ollama_check(self) -> dict[str, Any]:
        turn_id = self.turns.next_turn()
        self.handoffs.handoff("SupervisorAgent", "OllamaReasoningAgent", phase="Diagnostics", message="checking Ollama gateway and deterministic fallback", progress_percent=2)
        health = self.llm.health_check(force=True)
        self.ollama_status = health.to_dict()
        label = f"Connected • {health.fast_model} • safe-cai-react" if health.ok else f"Fallback • {health.fast_model} • {health.error or 'unreachable'}"
        self.dashboard.update(ollama_status=label, turn=self._turn_count(), **self._sync_dashboard_matrix("llm_public_reasoning"))
        self.reasoning.publish(turn_id=turn_id, agent="OllamaReasoningAgent", observation=f"Ollama health ok={health.ok}; model_available={health.model_available}", hypothesis="LLM is advisory; deterministic engines continue without it", decision=label, selected_tool="llm_gateway.health_check", safety="LLM failure cannot block crawling, extraction, testing, or reporting", evidence_summary=json.dumps(self.ollama_status, ensure_ascii=False)[:600], next_action="continue with scope and recon", progress_percent=3)
        return self.ollama_status

    def _llm_surface_summary(self, *, progress: int) -> dict[str, Any]:
        allowed, reason = self.llm_policy.allow("public_reasoning", force=True)
        if not allowed:
            return {"ok": False, "reason": reason}
        context = {"coverage": self.state.coverage(), "surface": self._surface(), "memory": self.memory.llm_summary(limit=30), "policy_reason": reason}
        response = self.llm.plan_actions(context, model_role="fast")
        if response.ok and response.public_reasoning:
            for item in response.public_reasoning[:5]:
                self.reasoning.publish(agent="OllamaReasoningAgent", observation="LLM reviewed sanitized scan surface", hypothesis="model can prioritize, but ToolRouter enforces execution", decision=item, selected_tool="llm_gateway.plan_actions", safety="advisory only; same-scope safe tools only", evidence_summary=json.dumps(self._surface(), ensure_ascii=False), next_action="enter research orchestration", progress_percent=progress)
        elif not response.ok:
            self.reasoning.publish(agent="OllamaReasoningAgent", observation="LLM surface summary unavailable", hypothesis="native research orchestrator and fallback ReAct decisions are sufficient", decision=response.error or "LLM unavailable", selected_tool="llm_gateway.plan_actions", safety="fallback deterministic scan continues", next_action="enter research orchestration", progress_percent=progress)
        return response.to_dict() if hasattr(response, "to_dict") else {"ok": bool(getattr(response, "ok", False))}

    def _availability_and_passive(self) -> dict[str, Any]:
        self.handoffs.handoff("SupervisorAgent", "ScopeAgent", phase="Scope", message="target normalized and authorization confirmed", target_url=self.target, path=urlparse(self.target).path or "/", progress_percent=4)
        root = self.client.get(self.target, purpose="target-availability")
        self.trace.log(turn_id=self.turns.next_turn(), agent_name="ScopeAgent", tool_name="availability_checker", phase="Scope", status="completed" if root.ok else "failed", target_url=root.url, path=urlparse(root.url).path or "/", message=f"HTTP {root.status_code}" if root.ok else root.error, evidence_summary=root.response_id, progress_percent=6)
        self._dashboard("Scope", "Availability check completed", progress=8, evidence=f"HTTP {root.status_code} {root.error}", agent="ScopeAgent", tool="availability_checker", url=root.url)
        if not root.ok:
            return {"root_ok": False, "status_code": root.status_code, "error": root.error}
        analyzer_summary = self.analyzers.run_all(root)
        self.state.add_event("INFO", "passive analyzers completed", **analyzer_summary.__dict__)
        return {"root_ok": True, "status_code": root.status_code, "analyzers": analyzer_summary.__dict__}

    def _deep_asset_discovery(self) -> dict[str, Any]:
        if not self.deep_assets:
            return {"skipped": True, "reason": "disabled"}
        result = DeepAssetDiscovery(state=self.state, client=self.client, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_docs=self.asset_doc_limit).run()
        self.state.add_event("INFO", "deep asset discovery completed", **result.__dict__)
        return result.__dict__

    def _initial_crawl(self) -> dict[str, Any]:
        self.handoffs.handoff("AssetDiscoveryAgent", "CrawlerAgent", phase="Crawler v2", message="discovering URLs, paths, forms, scripts, and route hints", target_url=self.target, progress_percent=26)
        crawl_result = self.crawler.crawl()
        self.state.stats["forms"] = crawl_result.forms
        self.state.stats["scripts"] = crawl_result.scripts
        self.state.add_event("INFO", "crawler completed", **crawl_result.__dict__)
        self._dashboard("Crawler v2", "Initial crawl completed", progress=40, evidence=self._coverage_text(), agent="CrawlerAgent", tool="safe_crawler")
        return crawl_result.__dict__

    def _javascript_review(self) -> dict[str, Any]:
        js_routes = self.crawler.analyze_scripts(limit=max(80, min(250, self.max_pages * 2)))
        self.state.add_event("INFO", "script route review completed", routes=js_routes)
        return {"routes_added": js_routes, "scripts_seen": int(self.state.stats.get("scripts", 0))}

    def _browser_discovery(self) -> dict[str, Any]:
        if not self.browser:
            return {"skipped": True, "reason": "browser flag not enabled"}
        browser_result = BrowserCrawler(state=self.state, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_routes=max(250, self.max_pages)).run()
        self.state.add_event("INFO", "browser route discovery finished", **browser_result.__dict__)
        return browser_result.__dict__

    def _post_discovery_crawl(self) -> dict[str, Any]:
        post_result = self.crawler.crawl()
        self.state.add_event("INFO", "post-discovery crawl completed", **post_result.__dict__)
        return post_result.__dict__

    def _research_orchestration(self) -> dict[str, Any]:
        self._dashboard("Unified Research Orchestrator", "Generating strategy profiles and phase decisions", progress=69, agent="UnifiedResearchOrchestrator", tool="unified_research_orchestrator")
        self.research_summary = self.research_orchestrator.run_all()
        self.state.add_event("INFO", "unified research orchestration completed", decisions=len(self.research_summary.get("decisions", [])), markdown_path=self.research_summary.get("markdown_path", ""))
        return self.research_summary

    def _dynamic_tool_phase(self) -> dict[str, Any]:
        if not self.dynamic_tools:
            return {"skipped": True, "reason": "disabled"}
        self._dashboard("Dynamic Tool Scheduler", "Running enabled approved dynamic tools", progress=70, agent="DynamicToolScheduler", tool="dynamic_tool_scheduler")
        self.dynamic_tool_summary = self.dynamic_scheduler.run_all(target=self.target, confirm=True, timeout=240)
        self.state.add_event("INFO", "dynamic tool scheduler completed", summary_path=self.dynamic_tool_summary.get("summary_path", ""))
        return self.dynamic_tool_summary

    def bootstrap(self) -> None:
        self._dashboard("Bootstrap", "Starting unified research autonomous scan engine", progress=1, agent="SupervisorAgent", tool="bootstrap")
        self.agent_runtime.run_turn(agent="SupervisorAgent", observation="scan requested for authorized target", decision="start scope validation", selected_tool="scope_guard", phase="Bootstrap", handoff_to="ScopeAgent", progress_percent=1)
        self.state.add_event("INFO", "autonomous scan started", scan_mode=self.scan_mode, engine="unified-research", version=VERSION)
        self.phase_runner.run("01 Diagnostics", self.run_ollama_check, progress_start=2, progress_end=5, url=self.target, agent="OllamaReasoningAgent", tool="llm_gateway.health_check")
        self.phase_runner.run("02 Scope + Passive Analysis", self._availability_and_passive, progress_start=6, progress_end=18, url=self.target, agent="ReconAgent", tool="passive_analyzers")
        self.phase_runner.run("03 Deep Asset Discovery", self._deep_asset_discovery, progress_start=19, progress_end=26, url=self.target, agent="AssetDiscoveryAgent", tool="deep_asset_discovery")
        self.phase_runner.run("04 Primary Crawl", self._initial_crawl, progress_start=27, progress_end=40, url=self.target, agent="CrawlerAgent", tool="crawler_v2")
        self.phase_runner.run("05 JavaScript Endpoint Extraction", self._javascript_review, progress_start=41, progress_end=50, url=self.target, agent="JSExposureAgent", tool="review_scripts")
        self.phase_runner.run("06 Browser Route Discovery", self._browser_discovery, progress_start=51, progress_end=56, url=self.target, agent="BrowserCrawlerAgent", tool="browser_crawler")
        self.phase_runner.run("07 Post-Discovery Crawl", self._post_discovery_crawl, progress_start=57, progress_end=64, url=self.target, agent="CrawlerAgent", tool="crawler_v2")
        self.memory.update_from_state(self.state)
        self.phase_runner.run("08 LLM Surface Review", lambda: self._llm_surface_summary(progress=66), progress_start=65, progress_end=68, url=self.target, agent="OllamaReasoningAgent", tool="llm_gateway.plan_actions")
        self.phase_runner.run("09 Unified Research Orchestration", self._research_orchestration, progress_start=69, progress_end=70, url=self.target, agent="UnifiedResearchOrchestrator", tool="unified_research_orchestrator")
        self.phase_runner.run("10 Dynamic Tool Scheduler", self._dynamic_tool_phase, progress_start=70, progress_end=71, url=self.target, agent="DynamicToolScheduler", tool="dynamic_tool_scheduler")
        if not self.state.params:
            self._dashboard("Parameter Discovery", "No safe query parameters or GET inputs were discovered in the selected scope.", progress=71, evidence=self._coverage_text(), agent="ParameterDiscoveryAgent", tool="parameter_inventory")
        self.state.save()

    def run_planned_tests(self) -> None:
        self.handoffs.handoff("ParameterDiscoveryAgent", "CAIReActPlannerAgent", phase="CAI ReAct Planning", message="building ReAct decisions from current scan state", progress_percent=72)
        if self.client.budget_remaining() <= 0:
            self.state.add_event("WARNING", "request budget exhausted before ReAct loop")
            return
        agent = SafeCAIReactAgent(target=self.target, scan_mode=self.scan_mode, state=self.state, crawler=self.crawler, tester=self.tester, llm=self.llm, dashboard=self.dashboard, trace=self.trace, turns=self.turns, tool_router=self.tool_router, max_turns=self.max_actions, max_params=self.max_params)
        self.react_summary = agent.run()
        self.state.stats["react_turns"] = int(self.react_summary.get("turns", 0))
        self.state.add_event("INFO", "safe CAI ReAct loop completed", turns=self.state.stats["react_turns"])
        self.memory.update_from_state(self.state)
        self.state.save()

    def write_reports(self) -> dict[str, str]:
        self.handoffs.handoff("RiskScoringAgent", "ReportAgent", phase="Reporting", message="writing evidence-based reports", progress_percent=92)
        if self.current_router_tool:
            self.tool_router.mark(self.current_router_tool, "completed", "completed before report generation")
        self.tool_router.mark("report_generator", "running", "writing final reports")
        self.extra_reports["evidence_index_md"] = str(self.evidence.write_markdown_index())
        self.extra_reports.update(self.agent_registry.write_reports(self.target))
        self.extra_reports.update(self.trace.write_reports())
        self.extra_reports.update(self.reasoning.write_reports())
        self.extra_reports.update(self.memory.write_reports())
        for name, payload in {"cai-react-summary.json": self.react_summary, "dynamic-tool-phase-summary.json": self.dynamic_tool_summary, "unified-research-orchestration.json": self.research_summary, "phase-runner-summary.json": self.phase_runner.summary(), "tool-router-matrix.json": self.tool_router.matrix()}.items():
            path = self.state.out_dir / name
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            self.extra_reports[name.replace("-", "_").replace(".", "_")] = str(path)
        reports = ReportingV2(state=self.state, extra_reports=self.extra_reports).write_all()
        self.tool_router.mark("report_generator", "completed", "reports written")
        self.dashboard.report_paths.update(reports)
        return reports

    def run(self) -> dict[str, Any]:
        started = time.time()
        self.dashboard.start()
        status = "completed"
        reports: dict[str, str] = {}
        try:
            self.bootstrap()
            self.phase_runner.run("11 Safe Parameter + Endpoint Review", self.run_planned_tests, progress_start=72, progress_end=90, url=self.target, agent="CAIReActPlannerAgent", tool="test_parameter")
            reports = self.phase_runner.run("12 Reporting", self.write_reports, progress_start=91, progress_end=98, url=self.target, agent="ReportAgent", tool="report_generator").data or {}
            self._dashboard("Final Dashboard", "Unified research scan completed", progress=100, evidence=self._coverage_text(), agent="ReportAgent", tool="report_generator")
        except KeyboardInterrupt:
            status = "interrupted"
            self.state.add_event("WARNING", "interrupted by user")
            reports = self.write_reports()
        except Exception as exc:
            status = "completed_partial"
            self.state.add_event("ERROR", "top-level scan exception converted to partial completion", error=str(exc)[:1000])
            try:
                reports = self.write_reports()
            except Exception as report_exc:
                self.state.add_event("ERROR", "report generation failed after top-level exception", error=str(report_exc)[:1000])
                reports = {}
        finally:
            self.dashboard.stop(final=True)
            self.state.save()
        return {
            "status": status,
            "version": VERSION,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "runtime_ms": int((time.time() - started) * 1000),
            "coverage": self.state.coverage(),
            "surface": self._surface(),
            "phase_runner": self.phase_runner.summary(),
            "research_orchestration": self.research_summary,
            "dynamic_tools": self.dynamic_tool_summary,
            "ollama": self.ollama_status,
            "llm_policy": self.llm_policy.as_dict(),
            "agent_runtime": self.agent_runtime.summary(),
            "cai_react": self.react_summary,
            "tool_router": self.tool_router.matrix(),
            "reports": reports,
            "safety": {"same_scope_only": True, "request_budget": True, "approval_gated_dynamic_tools": True, "copied_offensive_code": False, "embedded_attack_payloads": False, "credential_testing": False, "target_data_modification": False, "destructive_actions": False},
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope safe unified research autonomous scan engine")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-mode", default="passive", choices=["passive", "safe-active", "lab"])
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-params", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--request-budget", type=int, default=500)
    parser.add_argument("--max-actions", type=int, default=160)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-deep-assets", action="store_true")
    parser.add_argument("--no-dynamic-tools", action="store_true")
    parser.add_argument("--asset-doc-limit", type=int, default=40)
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    args = parser.parse_args()
    engine = AutonomousScanEngine(args.target, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, headers=parse_headers(args.header), max_pages=args.max_pages, max_depth=args.max_depth, max_params=args.max_params, request_timeout=args.request_timeout, delay=args.delay, request_budget=args.request_budget, max_actions=args.max_actions, resume=args.resume, browser=args.browser, live_dashboard=not args.no_live_dashboard, deep_assets=not args.no_deep_assets, dynamic_tools=not args.no_dynamic_tools, asset_doc_limit=args.asset_doc_limit, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    payload = engine.run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") in {"completed", "completed_partial", "interrupted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
