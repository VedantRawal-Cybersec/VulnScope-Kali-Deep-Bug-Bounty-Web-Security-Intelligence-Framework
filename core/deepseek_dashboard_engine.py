#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from typing import Any

from core.access_matrix import AccessMatrixEngine
from core.advisory_enrichment import AdvisoryEnrichment
from core.ai_brain import AIBrain
from core.api_discovery import APIDiscoveryEngine
from core.autonomous_scan_engine import AutonomousScanEngine, build_parser, parse_headers
from core.browser_network_capture import BrowserNetworkCapture
from core.deepseek_autonomy_loop import DeepSeekAutonomyLoop
from core.endpoint_artifact_importer import EndpointArtifactImporter
from core.ethical_methodology import EthicalMethodologyLedger
from core.final_report_index import FinalReportIndex
from core.safe_surface_engine import SafeSurfaceEngine
from core.scan_database import ScanDatabase
from core.security_scorecard import SecurityScorecard
from core.technology_intelligence import TechnologyIntelligence
from core.technology_test_planner import TechnologyTestPlanner
from core.tool_manifest_system import ToolManifestSystem


class DeepSeekDashboardEngine(AutonomousScanEngine):
    """Full dashboard engine with full orchestration modules before AI control."""

    def _run_technology_intelligence(self) -> dict[str, Any]:
        self._dashboard("Technology Intelligence", "Fingerprinting visible technologies and public advisory leads", progress=23, agent="TechnologyIntelAgent", tool="technology_intelligence")
        intel = TechnologyIntelligence(state=self.state, client=self.client, dashboard=self.dashboard, advisory_lookup=True, max_advisories=30).run()
        self.extra_reports.update(intel.get("reports", {}))
        self.state.add_event("INFO", "technology intelligence completed", summary=intel)
        self.state.save()
        return intel

    def _run_technology_planner(self) -> dict[str, Any]:
        self._dashboard("Technology Planner", "Building technology-driven test plan", progress=30, agent="TechnologyPlannerAgent", tool="technology_test_planner")
        result = TechnologyTestPlanner(state=self.state, dashboard=self.dashboard).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "technology test planner completed", summary=result)
        self.state.save()
        return result

    def _run_browser_network_capture(self) -> dict[str, Any]:
        self._dashboard("Browser Network Capture", "Capturing browser-observed routes when Playwright is available", progress=56, agent="BrowserNetworkAgent", tool="browser_network_capture")
        profiles_file = os.getenv("VULNSCOPE_AUTH_PROFILES_FILE", "")
        result = BrowserNetworkCapture(state=self.state, dashboard=self.dashboard, auth_profiles_file=profiles_file, max_pages=min(50, self.max_pages)).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "browser network capture completed", summary=result)
        self.state.save()
        return result

    def _run_endpoint_import(self) -> dict[str, Any]:
        files_env = os.getenv("VULNSCOPE_ENDPOINT_ARTIFACTS", "")
        files = [item.strip() for item in files_env.split(",") if item.strip()]
        self._dashboard("Endpoint Artifact Import", "Importing user supplied endpoint artifacts", progress=57, agent="EndpointImportAgent", tool="endpoint_artifact_import")
        result = EndpointArtifactImporter(state=self.state, dashboard=self.dashboard, files=files).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "endpoint artifact import completed", summary=result)
        self.state.save()
        return result

    def _run_api_discovery(self) -> dict[str, Any]:
        self._dashboard("API Discovery", "Discovering API documents and API-like routes", progress=76, agent="APIDiscoveryAgent", tool="api_discovery")
        seed_env = os.getenv("VULNSCOPE_API_SEEDS", "")
        seeds = [item.strip() for item in seed_env.split(",") if item.strip()]
        result = APIDiscoveryEngine(state=self.state, client=self.client, dashboard=self.dashboard, seed_urls=seeds, max_docs=60).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "api discovery completed", summary=result)
        self.state.save()
        return result

    def _run_access_matrix(self) -> dict[str, Any]:
        self._dashboard("Access Matrix", "Comparing authorized auth profiles if supplied", progress=78, agent="AccessMatrixAgent", tool="access_matrix")
        profiles_file = os.getenv("VULNSCOPE_AUTH_PROFILES_FILE", "")
        result = AccessMatrixEngine(state=self.state, client=self.client, dashboard=self.dashboard, auth_profiles_file=profiles_file, max_urls=min(120, self.max_pages)).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "access matrix completed", summary=result)
        self.state.save()
        return result

    def _run_tool_manifest_registry(self) -> dict[str, Any]:
        self._dashboard("Tool Manifest Registry", "Evaluating approved utility manifests", progress=79, agent="ToolManifestAgent", tool="tool_manifest_system")
        manifest_dir = os.getenv("VULNSCOPE_TOOL_MANIFEST_DIR", "tool_manifests")
        result = ToolManifestSystem(state=self.state, dashboard=self.dashboard, manifest_dir=manifest_dir).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "tool manifest registry completed", summary=result)
        self.state.save()
        return result

    def _run_advisory_enrichment(self) -> dict[str, Any]:
        self._dashboard("Advisory Enrichment", "Enriching public advisory leads", progress=81, agent="AdvisoryEnrichmentAgent", tool="advisory_enrichment")
        result = AdvisoryEnrichment(state=self.state, dashboard=self.dashboard).run()
        self.extra_reports.update(result.get("reports", {}))
        self.state.add_event("INFO", "advisory enrichment completed", summary=result)
        self.state.save()
        return result

    def _write_scorecard_and_index(self) -> dict[str, str]:
        score_reports = SecurityScorecard(state=self.state, extra_reports=self.extra_reports).write()
        self.extra_reports.update(score_reports)
        try:
            methodology = EthicalMethodologyLedger(state=self.state, mode=self.scan_mode, include_subdomains=self.include_subdomains, dynamic_ready=0).write()
            self.extra_reports.update(methodology)
        except Exception as exc:
            self.state.add_event("WARNING", "methodology ledger failed", error=str(exc)[:500])
        try:
            db_info = ScanDatabase().record(state=self.state, reports=self.extra_reports)
            self.extra_reports["sqlite_database"] = db_info["database"]
            self.extra_reports["sqlite_run_id"] = str(db_info["run_id"])
        except Exception as exc:
            self.state.add_event("WARNING", "sqlite recording failed", error=str(exc)[:500])
        index_reports = FinalReportIndex(state=self.state, reports=self.extra_reports, summary={"react_turns": len(self.react_summary.get("turns", []) if isinstance(self.react_summary, dict) else [])}).write()
        self.extra_reports.update(index_reports)
        return {**score_reports, **index_reports}

    def _safe_parameter_review(self) -> dict[str, Any]:
        intel = self._run_technology_intelligence()
        tech_plan = self._run_technology_planner()
        self._dashboard("Surface Mapping", "Mapping URLs, forms, parameters, scripts, and checks", progress=74, agent="SafeSurfaceEngine", tool="safe_surface_engine")
        surface = SafeSurfaceEngine(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard, max_pages=self.max_pages, max_depth=self.max_depth, max_params=self.max_params, mode=self.scan_mode, include_subdomains=self.include_subdomains).run_all()
        self.extra_reports.update(surface.get("reports", {}))
        self.state.add_event("INFO", "surface mapping completed", summary=surface)
        browser_capture = self._run_browser_network_capture()
        endpoint_import = self._run_endpoint_import()
        api = self._run_api_discovery()
        access = self._run_access_matrix()
        tool_registry = self._run_tool_manifest_registry()
        advisory = self._run_advisory_enrichment()
        self.state.save()

        self._dashboard("DeepSeek Autonomous ReAct", "DeepSeek is choosing the next action from mapped scan state", progress=82, agent="DeepSeekPlannerAgent", tool="deepseek_react_loop")
        brain = AIBrain(model=self.ollama_model or "deepseek-local")
        loop = DeepSeekAutonomyLoop(target=self.target, state=self.state, crawler=self.crawler, tester=self.tester, dashboard=self.dashboard, dynamic_scheduler=self.dynamic_scheduler, brain=brain, max_turns=min(max(20, self.max_actions), 120), max_params=self.max_params, scan_mode=self.scan_mode)
        self.react_summary = loop.run()
        self.react_summary["surface"] = surface
        self.react_summary["technology_intelligence"] = intel
        self.react_summary["technology_plan"] = tech_plan
        self.react_summary["browser_network_capture"] = browser_capture
        self.react_summary["endpoint_import"] = endpoint_import
        self.react_summary["api_discovery"] = api
        self.react_summary["access_matrix"] = access
        self.react_summary["tool_manifest_registry"] = tool_registry
        self.react_summary["advisory_enrichment"] = advisory
        if self.react_summary.get("summary_path"):
            self.extra_reports["deepseek_autonomy_summary"] = self.react_summary["summary_path"]
        if self.react_summary.get("markdown_path"):
            self.extra_reports["deepseek_autonomy_markdown"] = self.react_summary["markdown_path"]
        post_reports = self._write_scorecard_and_index()
        self.react_summary["post_reports"] = post_reports
        self.state.add_event("INFO", "deepseek autonomous react completed", turns=len(self.react_summary.get("turns", [])), summary_path=self.react_summary.get("summary_path", ""))
        self.state.save()
        return self.react_summary


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    engine = DeepSeekDashboardEngine(
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
        deep_assets=not args.no_deep_assets,
        dynamic_tools=not args.no_dynamic_tools,
        asset_doc_limit=args.asset_doc_limit,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
    )
    summary = engine.run()
    print(json.dumps({"ok": bool(summary.get("ok")), "coverage": summary.get("coverage"), "reports": summary.get("reports"), "react": summary.get("react")}, indent=2, ensure_ascii=False))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
