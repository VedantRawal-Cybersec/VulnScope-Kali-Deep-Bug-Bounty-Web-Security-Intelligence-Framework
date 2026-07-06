#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from typing import Any
from urllib.parse import urlparse

from cai_scope_guard import normalize_target
from core.agentic_framework import TraceLogger, TurnManager
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
from core.orchestration_contract import OrchestrationContract
from core.phase_runner import PhaseRunner
from core.phase_scheduler import PhaseScheduler
from core.reporting_v2 import ReportingV2
from core.safe_analyzers import PassiveAnalyzers
from core.scan_health import ScanHealthReporter
from core.scan_state import ScanState
from core.test_engine import TestEngine

VERSION = "1.17.7-strict-orchestration-contract"


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
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", os.getenv("OLLAMA_HOST", "http://localhost:11434"))
        self.ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "deepseek-local")
        os.environ["VULNSCOPE_SCAN_MODE"] = self.scan_mode

        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.dashboard.update(mode=self.scan_mode, authorization_status="confirmed")
        self.state = ScanState(self.target, resume=resume)
        self.state.stats.update({"max_pages": self.max_pages, "max_depth": self.max_depth, "scan_mode": self.scan_mode, "engine_version": VERSION, "include_subdomains": self.include_subdomains, "dynamic_tools_enabled": self.dynamic_tools, "browser_enabled": self.browser})

        self.evidence = EvidenceStore(self.target)
        self.client = SafeHttpClientV2(state=self.state, evidence=self.evidence, headers=headers or {}, timeout=request_timeout, delay=delay, request_budget=request_budget)
        self.crawler = CrawlerV2(state=self.state, client=self.client, max_pages=max_pages, max_depth=max_depth, include_subdomains=include_subdomains, dashboard=self.dashboard)
        self.tester = TestEngine(state=self.state, client=self.client, dashboard=self.dashboard)
        self.analyzers = PassiveAnalyzers(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard)
        self.llm_policy = LLMPolicy.from_env()
        self.llm = LLMGateway(ollama_url=self.ollama_url, fast_model=self.ollama_model, deep_model=os.getenv("VULNSCOPE_DEEP_MODEL", self.ollama_model), report_model=os.getenv("VULNSCOPE_REPORT_MODEL", self.ollama_model))
        self.memory = LLMMemory(self.target)
        self.turns = TurnManager()
        self.phase_runner = PhaseRunner(state=self.state, dashboard=self.dashboard, trace=None)
        self.dynamic_scheduler = PhaseScheduler(dashboard=self.dashboard, report_dir=self.state.out_dir, state=self.state, scan_mode=self.scan_mode)
        self.research_orchestrator = UnifiedResearchOrchestrator(state=self.state, dashboard=self.dashboard)
        self.trace = TraceLogger(self.target, scan_id=self.dashboard.snapshot.scan_id)

        self.extra_reports: dict[str, str] = {}
        self.ollama_status: dict[str, Any] = {}
        self.dynamic_tool_summary: dict[str, Any] = {}
        self.research_summary: dict[str, Any] = {}
        self.deep_scan_summary: dict[str, Any] = {}
        self.react_summary: dict[str, Any] = {}
        self.health_reports: dict[str, str] = {}
        self.orchestration_contract: dict[str, Any] = {}

    def _surface(self) -> dict[str, int]:
        paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
        api_like = [item.url for item in self.state.urls.values() if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()]
        return {"urls_found": len(self.state.urls), "paths_found": len(paths), "params_found": len(self.state.params), "forms_found": int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)), "js_found": int(self.state.stats.get("scripts", 0)), "api_routes_found": len(api_like) + int(self.state.stats.get("javascript_routes", 0))}

    def _coverage_text(self) -> str:
        cov = self.state.coverage()
        return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} findings={cov['findings']} timeouts={cov['timeouts']}"

    def _dash(self, phase: str, action: str, *, progress: int, agent: str, tool: str, status: str = "running", evidence: str = "", url: str | None = None) -> None:
        current = url or self.target
        parsed = urlparse(current)
        self.dashboard.update(phase=phase, phase_progress=progress, current_agent=agent, current_tool=tool, tool_status=status, decision=status, action=action, endpoint=current, request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""), path=parsed.path or "/", parameters=parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope.", evidence=evidence or self._coverage_text(), requests=int(self.state.stats.get("requests", 0)), findings=len(self.state.findings), **self._surface())
        self.dashboard.event("INFO" if status != "failed" else "ERROR", action)

    def run_ollama_check(self) -> dict[str, Any]:
        health = self.llm.health_check(force=True)
        self.ollama_status = health.to_dict()
        self.dashboard.update(ollama_status=("connected" if health.ok else "fallback"), current_tool="llm_gateway.health_check", tool_status="completed")
        return self.ollama_status

    def _availability_and_passive(self) -> dict[str, Any]:
        root = self.client.get(self.target, purpose="target-availability")
        self._dash("Scope", "Availability check completed", progress=8, agent="ScopeAgent", tool="availability_checker", status="completed" if root.ok else "failed", evidence=f"HTTP {root.status_code} {root.error}", url=root.url)
        if not root.ok:
            self.state.stats.update({"target_reachable": False, "target_reachability_error": root.error or f"HTTP {root.status_code}"})
            self.state.save()
            return {"root_ok": False, "status_code": root.status_code, "error": root.error or f"HTTP {root.status_code}"}
        self.state.stats["target_reachable"] = True
        summary = self.analyzers.run_all(root)
        self.dashboard.update(current_tool="passive_analyzers", tool_status="completed")
        self.state.add_event("INFO", "passive analyzers completed", **summary.__dict__)
        self.state.save()
        return {"root_ok": True, "status_code": root.status_code, "analyzers": summary.__dict__}

    def _deep_asset_discovery(self) -> dict[str, Any]:
        if not self.deep_assets:
            self.dashboard.update(current_tool="deep_asset_discovery", tool_status="inactive")
            return {"skipped": True, "reason": "disabled"}
        result = DeepAssetDiscovery(state=self.state, client=self.client, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_docs=self.asset_doc_limit).run()
        self.dashboard.update(current_tool="deep_asset_discovery", tool_status="completed")
        self.state.save()
        return result.__dict__

    def _initial_crawl(self) -> dict[str, Any]:
        result = self.crawler.crawl()
        self.state.stats["forms"] = result.forms
        self.state.stats["scripts"] = result.scripts
        self._dash("Crawler v2", "Initial crawl completed", progress=40, agent="CrawlerAgent", tool="crawler_v2", status="completed")
        self.state.save()
        return result.__dict__

    def _javascript_review(self) -> dict[str, Any]:
        routes = self.crawler.analyze_scripts(limit=max(80, min(250, self.max_pages * 2)))
        self.dashboard.update(current_tool="review_scripts", tool_status="completed")
        self.state.save()
        return {"routes_added": routes, "scripts_seen": int(self.state.stats.get("scripts", 0))}

    def _browser_discovery(self) -> dict[str, Any]:
        if not self.browser:
            self.dashboard.update(current_tool="browser_crawler", tool_status="inactive")
            return {"skipped": True, "reason": "browser flag not enabled"}
        result = BrowserCrawler(state=self.state, include_subdomains=self.include_subdomains, dashboard=self.dashboard, max_routes=max(250, self.max_pages)).run()
        self.dashboard.update(current_tool="browser_crawler", tool_status="completed")
        self.state.save()
        return result.__dict__

    def _post_discovery_crawl(self) -> dict[str, Any]:
        result = self.crawler.crawl()
        self.dashboard.update(current_tool="crawler_v2", tool_status="completed")
        self.state.save()
        return result.__dict__

    def _safe_deep_phase_pack(self) -> dict[str, Any]:
        self._dash("Deep Scan Phase Pack", "Running discovery enrichment", progress=60, agent="DeepScanPhasePack", tool="deep_scan_phase_pack")
        self.deep_scan_summary = DeepScanPhasePack(state=self.state, client=self.client, dashboard=self.dashboard, include_subdomains=self.include_subdomains).run_all()
        if self.deep_scan_summary.get("summary_path"):
            self.extra_reports["deep_scan_phase_summary"] = self.deep_scan_summary["summary_path"]
        self.dashboard.update(current_tool="deep_scan_phase_pack", tool_status="completed")
        self.state.save()
        return self.deep_scan_summary

    def _llm_surface_summary(self, *, progress: int) -> dict[str, Any]:
        allowed, reason = self.llm_policy.allow("public_reasoning", force=True)
        if not allowed:
            self.dashboard.update(current_tool="llm_gateway.plan_actions", tool_status="inactive")
            return {"skipped": True, "reason": reason}
        response = self.llm.plan_actions({"coverage": self.state.coverage(), "surface": self._surface(), "memory": self.memory.llm_summary(limit=20)}, model_role="fast")
        self.dashboard.update(current_tool="llm_gateway.plan_actions", tool_status="completed" if getattr(response, "ok", False) else "failed")
        return response.to_dict() if hasattr(response, "to_dict") else {"ok": bool(getattr(response, "ok", False))}

    def _research_orchestration(self) -> dict[str, Any]:
        self._dash("Unified Research Orchestrator", "Generating strategy profile", progress=72, agent="UnifiedResearchOrchestrator", tool="unified_research_orchestrator")
        self.research_summary = self.research_orchestrator.run_all()
        for key in ["markdown_path", "json_path", "summary_path"]:
            if self.research_summary.get(key):
                self.extra_reports[f"research_{key}"] = str(self.research_summary[key])
        self.dashboard.update(current_tool="unified_research_orchestrator", tool_status="completed")
        self.state.save()
        return self.research_summary

    def _dynamic_tool_phase(self) -> dict[str, Any]:
        if not self.dynamic_tools:
            self.dashboard.update(current_tool="dynamic_tool_scheduler", tool_status="inactive")
            return {"skipped": True, "reason": "disabled"}
        self._dash("Dynamic Tool Scheduler", "Running ready dynamic tools", progress=78, agent="DynamicToolScheduler", tool="dynamic_tool_scheduler")
        self.dynamic_tool_summary = self.dynamic_scheduler.run_all(target=self.target, confirm=True, timeout=240)
        if self.dynamic_tool_summary.get("summary_path"):
            self.extra_reports["dynamic_tool_phase_summary"] = self.dynamic_tool_summary["summary_path"]
        self.dashboard.update(current_tool="dynamic_tool_scheduler", tool_status="completed")
        self.state.save()
        return self.dynamic_tool_summary

    def _safe_parameter_review(self) -> dict[str, Any]:
        self._dash("Safe Parameter + Endpoint Review", "Running parameter review loop", progress=86, agent="CAIReActPlannerAgent", tool="cai_react_planner")
        planner = SafeCAIReactAgent(target=self.target, scan_mode=self.scan_mode, state=self.state, crawler=self.crawler, tester=self.tester, llm=self.llm, dashboard=self.dashboard, trace=self.trace, turns=self.turns, tool_router=None, max_turns=self.max_actions, max_params=self.max_params)
        self.react_summary = planner.run()
        path = self.state.out_dir / "cai-react-summary.json"
        path.write_text(json.dumps(self.react_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        self.extra_reports["cai_react_summary"] = str(path)
        self.dashboard.update(current_tool="cai_react_planner", tool_status="completed")
        self.state.save()
        return self.react_summary

    def _write_reports(self) -> dict[str, Any]:
        self._dash("Reporting", "Writing reports", progress=95, agent="ReportAgent", tool="report_generator")
        reports = ReportingV2(state=self.state, extra_reports=self.extra_reports).write_all()
        self.extra_reports.update(reports)
        health = ScanHealthReporter(state=self.state, phase_runner=self.phase_runner, dynamic_summary=self.dynamic_tool_summary, extra=self.extra_reports).write_all()
        self.health_reports = health
        self.extra_reports.update(health)
        self.orchestration_contract = OrchestrationContract(state=self.state, phase_runner=self.phase_runner, extra_reports=self.extra_reports, dynamic_summary=self.dynamic_tool_summary, react_summary=self.react_summary).write()
        for key, value in self.orchestration_contract.items():
            if isinstance(value, str):
                self.extra_reports[key] = value
        self.extra_reports.update(self.dashboard.write_reports(self.state.out_dir))
        self.trace.write_reports(self.state.out_dir)
        self.state.add_event("INFO", "reports written", reports=self.extra_reports, orchestration_contract=self.orchestration_contract)
        self.state.save()
        self.dashboard.update(current_tool="report_generator", tool_status="completed")
        return {"reports": self.extra_reports, "orchestration_contract": self.orchestration_contract}

    def bootstrap(self) -> dict[str, Any]:
        self.dashboard.start()
        try:
            self._dash("Bootstrap", "Starting scan engine", progress=1, agent="SupervisorAgent", tool="bootstrap")
            self.state.add_event("INFO", "autonomous scan started", scan_mode=self.scan_mode, version=VERSION)
            self.phase_runner.run("01 Diagnostics", self.run_ollama_check, progress_start=2, progress_end=5, url=self.target, agent="OllamaReasoningAgent", tool="llm_gateway.health_check")
            self.phase_runner.run("02 Scope + Passive Analysis", self._availability_and_passive, progress_start=6, progress_end=14, url=self.target, agent="ReconAgent", tool="passive_analyzers")
            self.phase_runner.run("03 Deep Asset Discovery", self._deep_asset_discovery, progress_start=15, progress_end=24, url=self.target, agent="AssetDiscoveryAgent", tool="deep_asset_discovery")
            self.phase_runner.run("04 Primary Crawl", self._initial_crawl, progress_start=25, progress_end=36, url=self.target, agent="CrawlerAgent", tool="crawler_v2")
            self.phase_runner.run("05 JavaScript Endpoint Extraction", self._javascript_review, progress_start=37, progress_end=44, url=self.target, agent="JSExposureAgent", tool="review_scripts")
            self.phase_runner.run("06 Browser Route Discovery", self._browser_discovery, progress_start=45, progress_end=52, url=self.target, agent="BrowserCrawlerAgent", tool="browser_crawler")
            self.phase_runner.run("07 Post-Discovery Crawl", self._post_discovery_crawl, progress_start=53, progress_end=59, url=self.target, agent="CrawlerAgent", tool="crawler_v2")
            self.phase_runner.run("08 Deep Scan Phase Pack", self._safe_deep_phase_pack, progress_start=60, progress_end=68, url=self.target, agent="DeepScanPhasePack", tool="deep_scan_phase_pack")
            self.phase_runner.run("09 LLM Surface Review", lambda: self._llm_surface_summary(progress=69), progress_start=69, progress_end=70, url=self.target, agent="OllamaReasoningAgent", tool="llm_gateway.plan_actions")
            self.phase_runner.run("10 Unified Research Orchestration", self._research_orchestration, progress_start=71, progress_end=75, url=self.target, agent="UnifiedResearchOrchestrator", tool="unified_research_orchestrator")
            self.phase_runner.run("11 Dynamic Tool Scheduler", self._dynamic_tool_phase, progress_start=76, progress_end=82, url=self.target, agent="DynamicToolScheduler", tool="dynamic_tool_scheduler")
            self.phase_runner.run("12 Safe Parameter + Endpoint Review", self._safe_parameter_review, progress_start=83, progress_end=92, url=self.target, agent="CAIReActPlannerAgent", tool="cai_react_planner")
            self.phase_runner.run("13 Reporting", self._write_reports, progress_start=93, progress_end=100, url=self.target, agent="ReportAgent", tool="report_generator", required=True)
            phase_summary = self.phase_runner.summary()
            contract_ok = bool(self.orchestration_contract.get("orchestration_contract_ok", True))
            required_failed = bool(phase_summary.get("failed_required", 0))
            summary = {"ok": bool(contract_ok and not required_failed), "version": VERSION, "target": self.target, "scan_mode": self.scan_mode, "phase_summary": phase_summary, "coverage": self.state.coverage(), "reports": self.extra_reports, "dynamic_tools": self.dynamic_tool_summary, "react": self.react_summary, "orchestration_contract": self.orchestration_contract}
            self.state.add_event("SUCCESS" if summary["ok"] else "WARNING", "autonomous scan completed", summary=summary)
            self.state.save()
            return summary
        finally:
            self.dashboard.stop(final=True)

    def run(self) -> dict[str, Any]:
        return self.bootstrap()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VulnScope autonomous engine")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-params", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--request-budget", type=int, default=500)
    parser.add_argument("--max-actions", type=int, default=160)
    parser.add_argument("--asset-doc-limit", type=int, default=40)
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", os.getenv("OLLAMA_HOST", "http://localhost:11434")))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "deepseek-local"))
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-deep-assets", action="store_true")
    parser.add_argument("--no-dynamic-tools", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine = AutonomousScanEngine(args.target, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, headers=parse_headers(args.header), max_pages=args.max_pages, max_depth=args.max_depth, max_params=args.max_params, request_timeout=args.request_timeout, delay=args.delay, request_budget=args.request_budget, max_actions=args.max_actions, resume=args.resume, browser=args.browser, live_dashboard=not args.no_live_dashboard, deep_assets=not args.no_deep_assets, dynamic_tools=not args.no_dynamic_tools, asset_doc_limit=args.asset_doc_limit, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    summary = engine.run()
    print(json.dumps({"ok": bool(summary.get("ok")), "coverage": summary.get("coverage"), "reports": summary.get("reports"), "orchestration_contract": summary.get("orchestration_contract")}, indent=2, ensure_ascii=False))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
