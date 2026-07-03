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
from core.ai_planner import AIPlanner
from core.browser_crawler import BrowserCrawler
from core.crawler_v2 import CrawlerV2
from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.live_dashboard import LiveDashboard
from core.llm_gateway import LLMGateway
from core.llm_memory import LLMMemory
from core.llm_policy import LLMPolicy
from core.parameter_inventory import dedupe_by_cluster
from core.reasoning_stream import ReasoningStream
from core.reporting_v2 import ReportingV2
from core.safe_analyzers import PassiveAnalyzers
from core.scan_quality import ScanQualityGate
from core.scan_state import ParamRecord, ScanState, TestRecord
from core.test_engine import TestEngine
from core.test_queue import TestQueueBuilder, test_requires_network
from core.tool_router import ToolRouter

VERSION = "1.11.0-execution-pipeline-quality-gate"


def parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            continue
        name, body = value.split(":", 1)
        if name.strip() and body.strip():
            headers[name.strip()] = body.strip()
    return headers


def find_param_for_test(state: ScanState, test: TestRecord) -> ParamRecord | None:
    for param in state.params.values():
        if param.url == test.url and param.name == test.parameter:
            return param
    return None


class AutonomousScanEngine:
    """CAI-style defensive scan coordinator with strict surface→parameter→test→evidence flow."""

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
        ollama_url: str | None = None,
        ollama_model: str | None = None,
        ollama_timeout: int | None = None,
        llm_health_mode: str | None = None,
    ) -> None:
        self.target = normalize_target(target)
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.include_subdomains = include_subdomains
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.max_params = max(1, int(max_params))
        self.max_actions = max(1, int(max_actions))
        self.browser = browser
        self.total_request_budget = max(1, int(request_budget))
        self.discovery_budget = max(10, int(self.total_request_budget * 0.60))
        self.test_budget = max(1, int(self.total_request_budget * 0.30))
        self.reserve_budget = max(0, self.total_request_budget - self.discovery_budget - self.test_budget)
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat")
        self.ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.ollama_timeout = int(ollama_timeout or os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "60"))
        self.llm_health_mode = llm_health_mode or os.getenv("VULNSCOPE_LLM_HEALTH_MODE", "tags-only")
        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.dashboard.update(mode=self.scan_mode, authorization_status="confirmed")
        self.state = ScanState(self.target, resume=resume)
        self.state.stats.update({
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "request_budget_total": self.total_request_budget,
            "budget_plan": {
                "total": self.total_request_budget,
                "discovery_budget": self.discovery_budget,
                "test_budget_reserved": self.test_budget,
                "reserve_budget": self.reserve_budget,
            },
        })
        self.evidence = EvidenceStore(self.target)
        self.client = SafeHttpClientV2(state=self.state, evidence=self.evidence, headers=headers or {}, timeout=request_timeout, delay=delay, request_budget=self.discovery_budget)
        self.crawler = CrawlerV2(state=self.state, client=self.client, max_pages=max_pages, max_depth=max_depth, include_subdomains=include_subdomains, dashboard=self.dashboard)
        self.tester = TestEngine(state=self.state, client=self.client, dashboard=self.dashboard)
        self.analyzers = PassiveAnalyzers(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard)
        self.planner = AIPlanner(ollama_url=self.ollama_url, model=self.ollama_model)
        self.agent_registry = AgentRegistry()
        self.trace = TraceLogger(self.target, scan_id=self.dashboard.snapshot.scan_id)
        self.handoffs = HandoffManager(self.trace, self.dashboard)
        self.turns = TurnManager()
        self.llm_policy = LLMPolicy.from_env()
        self.llm = LLMGateway(ollama_url=self.ollama_url, fast_model=self.ollama_model, deep_model=os.getenv("VULNSCOPE_DEEP_MODEL", self.ollama_model), report_model=os.getenv("VULNSCOPE_REPORT_MODEL", self.ollama_model), timeout=self.ollama_timeout, health_mode=self.llm_health_mode)
        self.reasoning = ReasoningStream(self.target, dashboard=self.dashboard, trace=self.trace)
        self.memory = LLMMemory(self.target)
        self.tool_router = ToolRouter()
        self.agent_runtime = AgentRuntime(target=self.target, dashboard=self.dashboard, trace=self.trace, reasoning=self.reasoning)
        self.extra_reports: dict[str, str] = {}
        self.ollama_status: dict[str, Any] = {}
        self.scan_quality: dict[str, Any] = {}

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
        return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} confirmed={cov['confirmed_vulnerabilities']} potential={cov['potential_review_leads']} info={cov['informational_observations']} timeouts={cov['timeouts']}"

    def _dashboard(self, phase: str, action: str, *, progress: int = 0, evidence: str = "", agent: str = "SupervisorAgent", tool: str = "autonomous_engine", decision: str = "—", url: str | None = None, parameter: str = "") -> None:
        current_url = url or self.target
        parsed = urlparse(current_url)
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        self.dashboard.update(
            phase=phase,
            phase_progress=progress,
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
            probe_string="autonomous-engine",
            hypothesis="surface → parameter inventory → test queue → execution → evidence validation → report",
            evidence=evidence or self._coverage_text(),
            safety_status="same-scope • GET/HEAD only • split request budget • no target data modification",
            **self._surface(),
        )
        self.dashboard.event("INFO", action)

    def _set_budget_phase(self, phase: str, budget_limit: int) -> None:
        self.client.request_budget = max(1, int(budget_limit))
        self.state.stats["active_budget_phase"] = phase
        self.state.stats.setdefault("budget_plan", {})[f"{phase}_limit"] = self.client.request_budget

    def run_ollama_check(self) -> None:
        turn_id = self.turns.next_turn()
        self.handoffs.handoff("SupervisorAgent", "OllamaReasoningAgent", phase="Diagnostics", message="checking Ollama gateway and fallback", progress_percent=2)
        self.tool_router.started("llm_public_reasoning", "Ollama health check")
        health = self.llm.health_check(force=True)
        self.ollama_status = health.to_dict()
        planner_mode = "advisory-enabled" if os.getenv("VULNSCOPE_USE_OLLAMA_PLANNER", "1") == "1" else "deterministic-only"
        label = f"Transport={health.transport_status} Model={health.model_status} Generation={health.generation_status} Mode={health.mode} Planner={planner_mode}"
        self.dashboard.update(ollama_status=label)
        if health.transport_ok and health.model_available:
            self.tool_router.completed("llm_public_reasoning", output_count=1, reason=label)
        elif health.generation_status == "timeout_or_invalid":
            self.tool_router.mark("llm_public_reasoning", "timed_out", label)
        else:
            self.tool_router.failed("llm_public_reasoning", health.error or "Ollama unavailable")
        self.reasoning.publish(
            turn_id=turn_id,
            agent="OllamaReasoningAgent",
            observation=f"Ollama transport={health.transport_status}; model={health.model_status}; generation={health.generation_status}",
            hypothesis="LLM is advisory and deterministic scanning remains authoritative",
            decision=label,
            selected_tool="llm_gateway.health_check",
            safety="LLM failure cannot block crawling, extraction, testing, or reporting",
            evidence_summary=json.dumps(self.ollama_status, ensure_ascii=False)[:800],
            next_action="continue with scope and recon",
            progress_percent=3,
        )

    def _llm_surface_summary(self, *, progress: int) -> None:
        allowed, reason = self.llm_policy.allow("public_reasoning", force=True)
        if not allowed:
            self.tool_router.skipped("llm_public_reasoning", reason)
            return
        context = {"coverage": self.state.coverage(), "surface": self._surface(), "memory": self.memory.llm_summary(limit=30), "policy_reason": reason}
        response = self.llm.plan_actions(context, model_role="fast")
        if response.ok and response.public_reasoning:
            self.tool_router.completed("llm_public_reasoning", output_count=len(response.public_reasoning), reason="public reasoning generated")
            for item in response.public_reasoning[:5]:
                self.reasoning.publish(
                    agent="OllamaReasoningAgent",
                    observation="LLM reviewed sanitized scan surface",
                    hypothesis="model can prioritize but cannot execute without guardrails",
                    decision=item,
                    selected_tool="llm_gateway.plan_actions",
                    safety="advisory only; deterministic planner and scope guard enforce execution",
                    evidence_summary=json.dumps(self._surface(), ensure_ascii=False),
                    next_action="continue deterministic scan loop",
                    progress_percent=progress,
                )
        elif not response.ok:
            self.tool_router.mark("llm_public_reasoning", "timed_out" if "timed" in response.error.lower() else "failed", response.error or "LLM unavailable")
            self.reasoning.publish(
                agent="OllamaReasoningAgent",
                observation="LLM surface summary unavailable",
                hypothesis="fallback mode is sufficient for scan progress",
                decision=response.error or "LLM unavailable",
                selected_tool="llm_gateway.plan_actions",
                safety="fallback deterministic scan continues",
                next_action="continue deterministic scan loop",
                progress_percent=progress,
            )

    def bootstrap(self) -> None:
        self._set_budget_phase("discovery", self.discovery_budget)
        self._dashboard("Bootstrap", "Starting autonomous scan engine", progress=1, agent="SupervisorAgent", tool="bootstrap")
        self.agent_runtime.run_turn(agent="SupervisorAgent", observation="scan requested for authorized target", decision="start scope validation", selected_tool="scope_guard", phase="Bootstrap", handoff_to="ScopeAgent", progress_percent=1)
        self.state.add_event("INFO", "autonomous scan started", scan_mode=self.scan_mode)
        self.run_ollama_check()

        self.handoffs.handoff("SupervisorAgent", "ScopeAgent", phase="Scope", message="target normalized and authorization confirmed", target_url=self.target, path=urlparse(self.target).path or "/", progress_percent=4)
        self.tool_router.started("availability_checker", "root availability")
        root = self.client.get(self.target, purpose="target-availability")
        self.tool_router.completed("availability_checker" if root.ok else "availability_checker", output_count=1, reason=f"HTTP {root.status_code}" if root.ok else root.error)
        self.trace.log(turn_id=self.turns.next_turn(), agent_name="ScopeAgent", tool_name="availability_checker", phase="Scope", status="completed" if root.ok else "failed", target_url=root.url, path=urlparse(root.url).path or "/", message=f"HTTP {root.status_code}" if root.ok else root.error, evidence_summary=root.response_id, progress_percent=6)

        self.handoffs.handoff("ScopeAgent", "ReconAgent", phase="Passive Analysis", message="running availability/header/cookie/metadata analyzers", target_url=root.url, path=urlparse(root.url).path or "/", progress_percent=7)
        for tool_id in ["header_analyzer", "cookie_analyzer", "metadata_checker"]:
            self.tool_router.started(tool_id, "passive analysis")
        analyzer_summary = self.analyzers.run_all(root)
        self.state.add_event("INFO", "passive analyzers completed", **analyzer_summary.__dict__)
        self.tool_router.completed("header_analyzer", output_count=1 if analyzer_summary.headers_checked else 0)
        self.tool_router.completed("cookie_analyzer", output_count=1 if analyzer_summary.cookies_checked else 0)
        self.tool_router.completed("metadata_checker", output_count=analyzer_summary.findings_added)
        self.agent_runtime.run_turn(agent="ReconAgent", observation="availability and passive metadata collected", decision="handoff to crawler", selected_tool="passive_analyzers", phase="Passive Analysis", handoff_to="CrawlerAgent", evidence_summary=str(analyzer_summary.__dict__), progress_percent=16)

        self.handoffs.handoff("ReconAgent", "CrawlerAgent", phase="Crawler v2", message="discovering URLs, paths, forms, scripts, and route hints", target_url=self.target, progress_percent=18)
        self.tool_router.started("crawler_v2", "static crawl and route extraction")
        crawl_result = self.crawler.crawl()
        self.state.stats["forms"] = crawl_result.forms
        self.state.stats["scripts"] = crawl_result.scripts
        self.state.add_event("INFO", "crawler completed", **crawl_result.__dict__)
        self.tool_router.completed("crawler_v2", output_count=crawl_result.urls_seen, reason=f"done={crawl_result.urls_done} params={crawl_result.parameters}")
        self.agent_runtime.run_turn(agent="CrawlerAgent", observation=f"crawler discovered {crawl_result.urls_seen} URLs and {crawl_result.parameters} parameters", decision="review JavaScript and browser surface", selected_tool="crawler_v2", phase="Crawler v2", handoff_to="JSExposureAgent", progress_percent=32)
        self._dashboard("Crawler v2", "Crawl completed", progress=32, evidence=self._coverage_text(), agent="CrawlerAgent", tool="safe_crawler")

        self.handoffs.handoff("CrawlerAgent", "JSExposureAgent", phase="JavaScript Route Review", message="extracting script route hints", progress_percent=34)
        self.tool_router.started("js_route_review", "external JavaScript route extraction")
        js_routes = self.crawler.analyze_scripts(limit=80)
        self.state.add_event("INFO", "script route review completed", routes=js_routes)
        self.tool_router.completed("js_route_review", output_count=js_routes)

        if self.browser:
            self.handoffs.handoff("JSExposureAgent", "CrawlerAgent", phase="Browser route discovery", message="transparent browser deep discovery", progress_percent=38)
            self.tool_router.started("browser_crawler", "browser route discovery")
            browser_result = BrowserCrawler(state=self.state, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_routes=max(250, self.max_pages), max_pages=min(max(5, self.max_pages // 4), 30)).run()
            self.state.add_event("INFO", "browser route discovery finished", **browser_result.__dict__)
            if browser_result.status == "completed":
                self.tool_router.completed("browser_crawler", output_count=browser_result.routes_added, reason=f"pages={browser_result.pages_rendered} params={browser_result.params_added}")
            elif browser_result.status == "skipped":
                self.tool_router.skipped("browser_crawler", browser_result.error)
            else:
                self.tool_router.failed("browser_crawler", browser_result.error)
            if browser_result.routes_added and self.client.budget_remaining() > 0:
                self.handoffs.handoff("CrawlerAgent", "CrawlerAgent", phase="Crawler v2", message="processing browser-discovered queued URLs", progress_percent=39)
                post_browser = self.crawler.crawl()
                self.state.add_event("INFO", "post-browser crawl completed", **post_browser.__dict__)
        else:
            self.tool_router.skipped("browser_crawler", "browser/render-js mode not enabled")

        self.memory.update_from_state(self.state)
        self._llm_surface_summary(progress=40)
        self.handoffs.handoff("CrawlerAgent", "ParameterDiscoveryAgent", phase="Parameter Discovery", message="parameter inventory ready" if self.state.params else "no safe GET/query parameters discovered", progress_percent=40)
        self.tool_router.completed("parameter_inventory", output_count=len(self.state.params), reason="parameter inventory finalized")
        if not self.state.params:
            self._dashboard("Parameter Discovery", "No safe query parameters or GET inputs were discovered in the selected scope.", progress=40, evidence=self._coverage_text(), agent="ParameterDiscoveryAgent", tool="parameter_inventory")
        self.state.stats.setdefault("budget_plan", {})["discovery_used"] = int(self.state.stats.get("requests", 0))
        self.state.save()

    def run_planned_tests(self) -> None:
        self._set_budget_phase("testing", self.total_request_budget)
        start_requests = int(self.state.stats.get("requests", 0))
        self.handoffs.handoff("ParameterDiscoveryAgent", "TestPlanningAgent", phase="Test Queue", message="building mandatory test queue", progress_percent=42)
        self.tool_router.started("test_queue_builder", "building explicit test queue")
        queue_builder = TestQueueBuilder(state=self.state, scan_mode=self.scan_mode, max_params=self.max_params)
        queue_summary = queue_builder.build()
        self.tool_router.completed("test_queue_builder", output_count=queue_summary.tests_created, reason=json.dumps(queue_summary.to_dict(), ensure_ascii=False))
        self.reasoning.publish(agent="TestPlanningAgent", observation=f"{queue_summary.parameters_considered} parameters considered", hypothesis="every parameter must produce at least a passive classification test", decision=f"queued {queue_summary.tests_created} new tests", selected_tool="test_queue_builder", safety="passive mode blocks canary tests; safe-active uses harmless GET-only canaries", evidence_summary=json.dumps(queue_summary.to_dict(), ensure_ascii=False), next_action="execute queued tests", progress_percent=43)

        tests = queue_builder.ordered_tests()
        if not tests:
            self.tool_router.skipped("classification_review", "no parameters available")
            if self.scan_mode == "passive":
                self.tool_router.blocked("safe_canary_reflection", "passive mode")
            else:
                self.tool_router.skipped("safe_canary_reflection", "no safe GET parameters")
            self.state.add_event("INFO", "no tests available after queue build", **queue_summary.to_dict())
            return

        classification_done = 0
        safe_active_done = 0
        skipped_for_budget = 0
        actions = 0
        self.tool_router.started("classification_review", "executing classification reviews")
        if self.scan_mode in {"safe-active", "lab"} and queue_summary.safe_active_tests:
            self.tool_router.started("safe_canary_reflection", "executing safe-active checks")
        else:
            self.tool_router.blocked("safe_canary_reflection", "passive mode" if self.scan_mode == "passive" else "no safe-active tests queued")

        for test in tests:
            if actions >= self.max_actions:
                break
            param = find_param_for_test(self.state, test)
            if param is None:
                test.status = "skipped"
                test.error = "parameter no longer exists"
                self.state.add_test(test)
                continue
            if test_requires_network(test.test_name) and self.client.budget_remaining() <= 0:
                test.status = "skipped"
                test.error = "test request budget exhausted"
                test.finished_at = time.time()
                self.state.add_test(test)
                skipped_for_budget += 1
                continue
            actions += 1
            turn_id = self.turns.next_turn()
            progress = 45 + int(actions * 40 / max(1, min(self.max_actions, len(tests))))
            self.handoffs.handoff("TestPlanningAgent", "SafeCanaryTestingAgent", phase="Safe Testing", message=f"running {test.test_name} for {param.name}", target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, progress_percent=progress)
            self.reasoning.publish(agent="SafeCanaryTestingAgent", observation=f"test={test.test_name} param={param.name} kind={param.kind}", hypothesis="execute queued safe test and validate deterministic evidence", decision=f"run {test.test_name}", selected_tool=test.test_name, safety="GET-only and same-scope guard enforced by SafeHttpClientV2", evidence_summary=self._coverage_text(), next_action="validate test outcome", turn_id=turn_id, progress_percent=progress)
            self.trace.log(turn_id=turn_id, agent_name="SafeCanaryTestingAgent", tool_name=test.test_name, phase="Safe Testing", status="running", target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, message="executing queued safe test", progress_percent=progress)
            outcome = self.tester.run_test(param, test.test_name)
            if test.test_name == "classification_review":
                classification_done += 1
            else:
                safe_active_done += 1
            self.trace.log(turn_id=turn_id, agent_name="FindingValidationAgent", tool_name=test.test_name, phase="Validation", status=outcome.status, target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, message=outcome.message, evidence_summary=str(outcome.evidence_id or ""), progress_percent=progress)

        self.tool_router.completed("classification_review", output_count=classification_done, reason=f"completed {classification_done} classification test(s)")
        if self.scan_mode in {"safe-active", "lab"}:
            if safe_active_done:
                self.tool_router.completed("safe_canary_reflection", output_count=safe_active_done, reason=f"completed {safe_active_done} safe-active test(s)")
            elif skipped_for_budget:
                self.tool_router.skipped("safe_canary_reflection", "test budget exhausted before safe-active checks")
        self.state.stats["planner_actions"] = actions
        self.state.stats["test_execution"] = {
            "tests_seen": len(tests),
            "actions_executed": actions,
            "classification_done": classification_done,
            "safe_active_done": safe_active_done,
            "skipped_for_budget": skipped_for_budget,
            "test_requests_used": int(self.state.stats.get("requests", 0)) - start_requests,
        }
        self.state.stats.setdefault("budget_plan", {})["testing_started_at_requests"] = start_requests
        self.state.stats.setdefault("budget_plan", {})["testing_finished_at_requests"] = int(self.state.stats.get("requests", 0))
        self.memory.update_from_state(self.state)
        self.state.save()

    def write_reports(self) -> dict[str, str]:
        self.handoffs.handoff("RiskScoringAgent", "ReportAgent", phase="Reporting", message="writing evidence-based reports", progress_percent=92)
        self.tool_router.started("scan_quality_gate", "evaluating scan quality")
        quality_gate = ScanQualityGate(state=self.state, ollama=self.ollama_status, tool_matrix=self.tool_router.matrix())
        quality = quality_gate.evaluate()
        self.scan_quality = quality.to_dict()
        quality_reports = quality_gate.write_reports(quality)
        self.tool_router.completed("scan_quality_gate", output_count=len(quality.issues), reason=f"grade={quality.grade} score={quality.score}")
        self.tool_router.started("report_generator", "writing final reports")
        self.extra_reports["evidence_index_md"] = str(self.evidence.write_markdown_index())
        self.extra_reports.update(self.agent_registry.write_reports(self.target))
        self.extra_reports.update(self.trace.write_reports())
        self.extra_reports.update(self.reasoning.write_reports())
        self.extra_reports.update(self.memory.write_reports())
        self.extra_reports.update(quality_reports)
        self.extra_reports["tool_router_matrix"] = json.dumps(self.tool_router.matrix(), ensure_ascii=False)
        reports = ReportingV2(state=self.state, extra_reports=self.extra_reports).write_all()
        self.tool_router.completed("report_generator", output_count=len(reports), reason="reports written")
        self.dashboard.report_paths.update(reports)
        return reports

    def run(self) -> dict[str, Any]:
        started = time.time()
        self.dashboard.start()
        try:
            self.bootstrap()
            self.run_planned_tests()
            reports = self.write_reports()
            self._dashboard("Final Dashboard", "Autonomous scan completed", progress=100, evidence=self._coverage_text(), agent="ReportAgent", tool="report_generator")
            return {
                "status": "completed",
                "version": VERSION,
                "target": self.target,
                "scan_mode": self.scan_mode,
                "runtime_ms": int((time.time() - started) * 1000),
                "coverage": self.state.coverage(),
                "scan_quality": self.scan_quality,
                "tool_matrix": self.tool_router.matrix(),
                "ollama": self.ollama_status,
                "llm_policy": self.llm_policy.as_dict(),
                "agent_runtime": self.agent_runtime.summary(),
                "reports": reports,
                "safety": {"same_scope_only": True, "transparent_user_agent": True, "request_budget": True, "split_budget": True, "adaptive_backoff": True, "resume_supported": True, "hidden_routing": False, "target_data_modification": False},
            }
        except KeyboardInterrupt:
            self.state.add_event("WARNING", "interrupted by user")
            reports = self.write_reports()
            return {"status": "interrupted", "version": VERSION, "target": self.target, "coverage": self.state.coverage(), "reports": reports}
        finally:
            self.dashboard.stop(final=False)
            self.state.save()


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope autonomous safe scan engine")
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
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    parser.add_argument("--ollama-timeout", type=int, default=int(os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "60")))
    parser.add_argument("--llm-health-mode", choices=["tags-only", "full", "disabled"], default=os.getenv("VULNSCOPE_LLM_HEALTH_MODE", "tags-only"))
    args = parser.parse_args()
    os.environ["VULNSCOPE_OLLAMA_TIMEOUT"] = str(args.ollama_timeout)
    os.environ["VULNSCOPE_LLM_HEALTH_MODE"] = args.llm_health_mode
    engine = AutonomousScanEngine(args.target, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, headers=parse_headers(args.header), max_pages=args.max_pages, max_depth=args.max_depth, max_params=args.max_params, request_timeout=args.request_timeout, delay=args.delay, request_budget=args.request_budget, max_actions=args.max_actions, resume=args.resume, browser=args.browser, live_dashboard=not args.no_live_dashboard, ollama_url=args.ollama_url, ollama_model=args.ollama_model, ollama_timeout=args.ollama_timeout, llm_health_mode=args.llm_health_mode)
    payload = engine.run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") in {"completed", "interrupted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
