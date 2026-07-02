#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any

from cai_scope_guard import normalize_target
from core.ai_planner import AIPlanner
from core.browser_crawler import BrowserCrawler
from core.crawler_v2 import CrawlerV2
from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.live_dashboard import LiveDashboard
from core.parameter_inventory import dedupe_by_cluster
from core.reporting_v2 import ReportingV2
from core.scan_state import ScanState
from core.test_engine import TestEngine

VERSION = "1.8.0-autonomous-scan-engine"


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
    """Real autonomous scan coordinator: state, crawl, inventory, tests, AI planning, evidence, reporting."""

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
        self.dashboard = LiveDashboard(self.target, max_turns=max_actions, enabled=True, live_stream=live_dashboard)
        self.state = ScanState(self.target, resume=resume)
        self.evidence = EvidenceStore(self.target)
        self.client = SafeHttpClientV2(state=self.state, evidence=self.evidence, headers=headers or {}, timeout=request_timeout, delay=delay, request_budget=request_budget)
        self.crawler = CrawlerV2(state=self.state, client=self.client, max_pages=max_pages, max_depth=max_depth, include_subdomains=include_subdomains, dashboard=self.dashboard)
        self.tester = TestEngine(state=self.state, client=self.client, dashboard=self.dashboard)
        self.planner = AIPlanner(ollama_url=ollama_url, model=ollama_model)
        self.extra_reports: dict[str, str] = {}

    def _coverage_text(self) -> str:
        cov = self.state.coverage()
        return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} findings={cov['findings']} timeouts={cov['timeouts']}"

    def _dashboard(self, phase: str, action: str, *, progress: int = 0, evidence: str = "") -> None:
        self.dashboard.update(
            phase=phase,
            phase_progress=progress,
            requests=self.state.stats.get("requests", 0),
            findings=len(self.state.findings),
            action=action,
            probe_string="autonomous-engine",
            hypothesis="AI planner coordinates crawler, inventory, safe tests, evidence, and reporting",
            evidence=evidence or self._coverage_text(),
            safety_status="same-scope • transparent user agent • request budget • resumable state • no target data modification",
        )
        self.dashboard.event("INFO", action)

    def bootstrap(self) -> None:
        self._dashboard("Bootstrap", "Starting autonomous scan engine", progress=1)
        self.state.add_event("INFO", "autonomous scan started", scan_mode=self.scan_mode)
        crawl_result = self.crawler.crawl()
        self.state.add_event("INFO", "crawler completed", **crawl_result.__dict__)
        self._dashboard("Crawler v2", "Crawl completed", progress=25, evidence=self._coverage_text())
        js_routes = self.crawler.analyze_scripts(limit=30)
        self.state.add_event("INFO", "script route review completed", routes=js_routes)
        if self.browser:
            browser_result = BrowserCrawler(state=self.state, include_subdomains=self.include_subdomains, dashboard=self.dashboard).run()
            self.state.add_event("INFO", "browser route discovery finished", **browser_result.__dict__)
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
        while actions < self.max_actions and self.client.budget_remaining() > 0:
            actions += 1
            progress = int(actions * 100 / self.max_actions)
            decision = self.planner.decide(self.state)
            self.state.add_event("INFO", "planner decision", **decision.__dict__)
            self._dashboard("AI Planner", f"Decision: {decision.action} — {decision.reason}", progress=progress)
            if decision.action == "crawl":
                self.crawler.crawl()
                self.crawler.analyze_scripts(limit=10)
                continue
            if decision.action == "review_scripts":
                self.crawler.analyze_scripts(limit=30)
                continue
            if decision.action == "test_parameter":
                param = AIPlanner.find_param(self.state, decision.url, decision.parameter)
                if param is None:
                    queued = dedupe_by_cluster(self.state.queued_params(limit=20), max_per_cluster=2)
                    param = queued[0] if queued else None
                if param is None:
                    self.state.add_event("INFO", "no parameter available for testing")
                    break
                if len(param.tested) >= 3:
                    param.status = "done"
                    self.state.save()
                    continue
                test_name = self.next_test_name(param.kind, decision.test_name)
                if test_name in param.tested:
                    test_name = "classification_review" if "classification_review" not in param.tested else "baseline"
                self.tester.run_test(param, test_name)
                continue
            if decision.action == "write_reports":
                break
            if decision.action == "stop":
                break
        self.state.stats["planner_actions"] = actions
        self.state.save()

    def write_reports(self) -> dict[str, str]:
        self.extra_reports["evidence_index_md"] = str(self.evidence.write_markdown_index())
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
            self._dashboard("Final Dashboard", "Autonomous scan completed", progress=100, evidence=self._coverage_text())
            return {
                "status": "completed",
                "version": VERSION,
                "target": self.target,
                "scan_mode": self.scan_mode,
                "runtime_ms": int((time.time() - started) * 1000),
                "coverage": self.state.coverage(),
                "reports": reports,
                "safety": {
                    "same_scope_only": True,
                    "transparent_user_agent": True,
                    "request_budget": True,
                    "adaptive_backoff": True,
                    "resume_supported": True,
                    "hidden_routing": False,
                    "target_data_modification": False,
                },
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
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    args = parser.parse_args()
    engine = AutonomousScanEngine(
        args.target,
        scan_mode=args.scan_mode,
        include_subdomains=args.include_subdomains,
        headers=parse_headers(args.header),
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        max_params=args.max_params,
        request_timeout=args.request_timeout,
        delay=args.delay,
        request_budget=args.request_budget,
        max_actions=args.max_actions,
        resume=args.resume,
        browser=args.browser,
        live_dashboard=not args.no_live_dashboard,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
    )
    payload = engine.run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") in {"completed", "interrupted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
