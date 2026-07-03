#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any
from urllib.parse import urlparse

from cai_scope_guard import normalize_target
from vulnscope_preflight import check_ollama
from core.agentic_framework import AgentRegistry, HandoffManager, TraceLogger, TurnManager
from core.ai_planner import AIPlanner
from core.browser_crawler import BrowserCrawler
from core.crawler_v2 import CrawlerV2
from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.live_dashboard import LiveDashboard
from core.parameter_inventory import dedupe_by_cluster
from core.reporting_v2 import ReportingV2
from core.safe_analyzers import PassiveAnalyzers
from core.scan_state import ScanState
from core.test_engine import TestEngine

VERSION = "1.9.1-scope-crawl-ollama-fallback"


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
    """CAI-style defensive scan coordinator: agents, handoffs, turns, evidence, safe tools, and reports."""

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
    ) -> None:
        self.target = normalize_target(target)
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.include_subdomains = include_subdomains
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.max_params = max(1, int(max_params))
        self.max_actions = max(1, int(max_actions))
        self.browser = browser
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate")
        self.ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.dashboard.update(mode=self.scan_mode, authorization_status="confirmed")
        self.state = ScanState(self.target, resume=resume)
        self.state.stats["max_pages"] = self.max_pages
        self.state.stats["max_depth"] = self.max_depth
        self.evidence = EvidenceStore(self.target)
        self.client = SafeHttpClientV2(state=self.state, evidence=self.evidence, headers=headers or {}, timeout=request_timeout, delay=delay, request_budget=request_budget)
        self.crawler = CrawlerV2(state=self.state, client=self.client, max_pages=max_pages, max_depth=max_depth, include_subdomains=include_subdomains, dashboard=self.dashboard)
        self.tester = TestEngine(state=self.state, client=self.client, dashboard=self.dashboard)
        self.analyzers = PassiveAnalyzers(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard)
        self.planner = AIPlanner(ollama_url=self.ollama_url, model=self.ollama_model)
        self.agent_registry = AgentRegistry()
        self.trace = TraceLogger(self.target, scan_id=self.dashboard.snapshot.scan_id)
        self.handoffs = HandoffManager(self.trace, self.dashboard)
        self.turns = TurnManager()
        self.extra_reports: dict[str, str] = {}
        self.ollama_status: dict[str, Any] = {}

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
            hypothesis="agents coordinate scope, recon, crawl, parameter discovery, safe tests, validation, scoring, and reporting",
            evidence=evidence or self._coverage_text(),
            safety_status="same-scope • GET/HEAD only • request budget • resumable state • no target data modification",
            **self._surface(),
        )
        self.dashboard.event("INFO", action)

    def run_ollama_check(self) -> None:
        turn_id = self.turns.next_turn()
        self.handoffs.handoff("SupervisorAgent", "OllamaReasoningAgent", phase="Diagnostics", message="checking model service and deterministic fallback", progress_percent=2)
        self.trace.log(turn_id=turn_id, agent_name="OllamaReasoningAgent", tool_name="ollama_diagnostics", phase="Diagnostics", status="running", target_url=self.target, message="checking model availability", progress_percent=2)
        try:
            status = check_ollama(generate_url=self.ollama_url, model=self.ollama_model, auto_pull_model=False)
        except Exception as exc:
            status = {"ok": False, "service": "error", "model": self.ollama_model, "error": str(exc)[:500]}
        self.ollama_status = status
        planner_mode = "advisory-enabled" if os.getenv("VULNSCOPE_USE_OLLAMA_PLANNER", "0") == "1" else "deterministic-fallback"
        label = f"Connected • {self.ollama_model} • {planner_mode}" if status.get("ok") else f"Fallback • {self.ollama_model} • {status.get('service', 'unreachable')}"
        self.dashboard.update(ollama_status=label)
        self.trace.log(turn_id=turn_id, agent_name="OllamaReasoningAgent", tool_name="ollama_diagnostics", phase="Diagnostics", status="completed" if status.get("ok") else "fallback", target_url=self.target, message=label, evidence_summary=json.dumps(status, ensure_ascii=False)[:600], progress_percent=3)

    def bootstrap(self) -> None:
        self._dashboard("Bootstrap", "Starting autonomous scan engine", progress=1, agent="SupervisorAgent", tool="bootstrap")
        self.state.add_event("INFO", "autonomous scan started", scan_mode=self.scan_mode)
        self.run_ollama_check()
        self.handoffs.handoff("SupervisorAgent", "ScopeAgent", phase="Scope", message="target normalized and authorization confirmed", target_url=self.target, path=urlparse(self.target).path or "/", progress_percent=4)
        root = self.client.get(self.target, purpose="target-availability")
        self.trace.log(turn_id=self.turns.next_turn(), agent_name="ScopeAgent", tool_name="availability_checker", phase="Scope", status="completed" if root.ok else "failed", target_url=root.url, path=urlparse(root.url).path or "/", message=f"HTTP {root.status_code}" if root.ok else root.error, evidence_summary=root.response_id, progress_percent=6)
        self.handoffs.handoff("ScopeAgent", "ReconAgent", phase="Passive Analysis", message="running availability/header/cookie/metadata analyzers", target_url=root.url, path=urlparse(root.url).path or "/", progress_percent=7)
        analyzer_summary = self.analyzers.run_all(root)
        self.state.add_event("INFO", "passive analyzers completed", **analyzer_summary.__dict__)
        self.handoffs.handoff("ReconAgent", "CrawlerAgent", phase="Crawler v2", message="discovering URLs, paths, forms, scripts, and route hints", target_url=self.target, progress_percent=18)
        crawl_result = self.crawler.crawl()
        self.state.stats["forms"] = crawl_result.forms
        self.state.stats["scripts"] = crawl_result.scripts
        self.state.add_event("INFO", "crawler completed", **crawl_result.__dict__)
        self._dashboard("Crawler v2", "Crawl completed", progress=32, evidence=self._coverage_text(), agent="CrawlerAgent", tool="safe_crawler")
        self.handoffs.handoff("CrawlerAgent", "JSExposureAgent", phase="JavaScript Route Review", message="extracting script route hints", progress_percent=34)
        js_routes = self.crawler.analyze_scripts(limit=80)
        self.state.add_event("INFO", "script route review completed", routes=js_routes)
        if self.browser:
            self.handoffs.handoff("JSExposureAgent", "CrawlerAgent", phase="Browser route discovery", message="optional transparent browser discovery", progress_percent=38)
            browser_result = BrowserCrawler(state=self.state, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_routes=max(250, self.max_pages)).run()
            self.state.add_event("INFO", "browser route discovery finished", **browser_result.__dict__)
            if browser_result.routes_added:
                self.handoffs.handoff("CrawlerAgent", "CrawlerAgent", phase="Crawler v2", message="processing browser-discovered queued URLs", progress_percent=39)
                post_browser = self.crawler.crawl()
                self.state.add_event("INFO", "post-browser crawl completed", **post_browser.__dict__)
        self.handoffs.handoff("CrawlerAgent", "ParameterDiscoveryAgent", phase="Parameter Discovery", message="parameter inventory ready" if self.state.params else "no safe GET/query parameters discovered", progress_percent=40)
        if not self.state.params:
            self._dashboard("Parameter Discovery", "No safe query parameters or GET inputs were discovered in the selected scope.", progress=40, evidence=self._coverage_text(), agent="ParameterDiscoveryAgent", tool="parameter_inventory")
        self.state.save()

    def next_test_name(self, param_kind: str, proposed: str) -> str:
        if self.scan_mode == "passive":
            return "classification_review"
        if proposed in {"reflection_canary", "error_behavior", "redirect_review", "classification_review"}:
            if proposed == "redirect_review" and param_kind not in {"route-like", "reference-like"}:
                return "reflection_canary"
            return proposed
        if param_kind in {"route-like", "reference-like"}:
            return "redirect_review"
        return "reflection_canary"

    def run_planned_tests(self) -> None:
        actions = 0
        self.handoffs.handoff("ParameterDiscoveryAgent", "PlannerAgent", phase="AI Planning", message="building turn-by-turn safe test queue", progress_percent=42)
        while actions < self.max_actions and self.client.budget_remaining() > 0:
            actions += 1
            turn_id = self.turns.next_turn()
            progress = 42 + int(actions * 45 / max(1, self.max_actions))
            decision = self.planner.decide(self.state)
            self.state.add_event("INFO", "planner decision", **decision.__dict__)
            self.trace.log(turn_id=turn_id, agent_name="PlannerAgent", tool_name="ai_planner", phase="AI Planning", status="completed", target_url=decision.url or self.target, parameter=decision.parameter, message=decision.reason, progress_percent=progress)
            self._dashboard("AI Planning", f"Decision: {decision.action} — {decision.reason}", progress=progress, agent="PlannerAgent", tool="ai_planner", decision=decision.action, url=decision.url or self.target, parameter=decision.parameter)
            if decision.action == "crawl":
                self.handoffs.handoff("PlannerAgent", "CrawlerAgent", phase="Crawler v2", message="continuing crawl from queued URLs", progress_percent=progress)
                self.crawler.crawl()
                self.crawler.analyze_scripts(limit=20)
                continue
            if decision.action == "review_scripts":
                self.handoffs.handoff("PlannerAgent", "JSExposureAgent", phase="JavaScript Route Review", message="reviewing script route hints", progress_percent=progress)
                self.crawler.analyze_scripts(limit=80)
                continue
            if decision.action == "test_parameter":
                param = AIPlanner.find_param(self.state, decision.url, decision.parameter)
                if param is None:
                    queued = dedupe_by_cluster(self.state.queued_params(limit=self.max_params), max_per_cluster=2)
                    param = queued[0] if queued else None
                if param is None:
                    self.state.add_event("INFO", "no parameter available for testing")
                    self._dashboard("Safe Testing", "No safe query parameters or GET inputs were discovered in the selected scope.", progress=progress, agent="SafeCanaryTestingAgent", tool="safe_canary_tester")
                    break
                if len(param.tested) >= 3:
                    param.status = "done"
                    self.state.save()
                    continue
                test_name = self.next_test_name(param.kind, decision.test_name)
                if test_name in param.tested:
                    test_name = "classification_review" if "classification_review" not in param.tested else "baseline"
                self.handoffs.handoff("PlannerAgent", "SafeCanaryTestingAgent", phase="Safe Testing", message=f"running {test_name} for {param.name}", target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, progress_percent=progress)
                self.trace.log(turn_id=turn_id, agent_name="SafeCanaryTestingAgent", tool_name=test_name, phase="Safe Testing", status="running", target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, message="executing safe parameter test", progress_percent=progress)
                outcome = self.tester.run_test(param, test_name)
                self.trace.log(turn_id=turn_id, agent_name="FindingValidationAgent", tool_name=test_name, phase="Validation", status=outcome.status, target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, message=outcome.message, evidence_summary=str(outcome.evidence_id or ""), progress_percent=progress)
                continue
            if decision.action in {"write_reports", "stop"}:
                break
        self.state.stats["planner_actions"] = actions
        self.state.save()

    def write_reports(self) -> dict[str, str]:
        self.handoffs.handoff("RiskScoringAgent", "ReportAgent", phase="Reporting", message="writing evidence-based reports", progress_percent=92)
        self.extra_reports["evidence_index_md"] = str(self.evidence.write_markdown_index())
        self.extra_reports.update(self.agent_registry.write_reports(self.target))
        self.extra_reports.update(self.trace.write_reports())
        reports = ReportingV2(state=self.state, extra_reports=self.extra_reports).write_all()
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
            return {"status": "completed", "version": VERSION, "target": self.target, "scan_mode": self.scan_mode, "runtime_ms": int((time.time() - started) * 1000), "coverage": self.state.coverage(), "ollama": self.ollama_status, "reports": reports, "safety": {"same_scope_only": True, "transparent_user_agent": True, "request_budget": True, "adaptive_backoff": True, "resume_supported": True, "hidden_routing": False, "target_data_modification": False}}
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
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    args = parser.parse_args()
    engine = AutonomousScanEngine(args.target, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, headers=parse_headers(args.header), max_pages=args.max_pages, max_depth=args.max_depth, max_params=args.max_params, request_timeout=args.request_timeout, delay=args.delay, request_budget=args.request_budget, max_actions=args.max_actions, resume=args.resume, browser=args.browser, live_dashboard=not args.no_live_dashboard, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    payload = engine.run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") in {"completed", "interrupted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
