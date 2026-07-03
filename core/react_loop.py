#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.crawler import CrawlConfig, SafeCrawler
from core.live_dashboard import LiveDashboard
from core.ollama_brain import batch_next_actions, think
from core.parameter_extractor import ParameterRecord
from core.vulnerability_tester import SafeVulnerabilityTester

DEFAULT_PLAN = ["target_profile", "passive_recon", "input_inventory", "evidence_review", "evidence_scoring", "report"]


def _records(items: list[dict[str, Any]]) -> list[ParameterRecord]:
    out: list[ParameterRecord] = []
    for item in items:
        try:
            out.append(ParameterRecord(**item))
        except Exception:
            continue
    return out


def run_modern_scan(target: str, *, render_js: bool = True, max_pages: int = 300, min_pages_goal: int = 200, max_depth: int = 3, threads: int = 8, delay: float = 0.2, request_timeout: int = 10, scan_mode: str = "passive", include_subdomains: bool = False, respect_robots: bool = True, live_dashboard: bool = True, final_dashboard: bool = True) -> dict[str, Any]:
    target = normalize_target(target)
    dashboard = LiveDashboard(target, max_turns=max_pages, enabled=True, live_stream=live_dashboard)
    dashboard.update(mode=scan_mode, current_agent="SupervisorAgent", current_tool="react_loop", action="Initializing modern browser-aware scan")
    dashboard.start()
    started = time.time()
    try:
        crawler = SafeCrawler(CrawlConfig(target=target, render_js=render_js, max_pages=max_pages, min_pages_goal=min_pages_goal, max_depth=max_depth, delay=delay, include_subdomains=include_subdomains, respect_robots=respect_robots), dashboard=dashboard)
        crawl = crawler.run()
        params = _records(crawl.parameters)
        safe_count = sum(1 for p in params if p.safe_to_test)
        dashboard.update(phase="Parameter Discovery", phase_progress=55, current_agent="ParameterDiscoveryAgent", current_tool="parameter_extractor", action=f"Parameter inventory built: total={len(params)} safe={safe_count}", urls_found=len(crawl.urls), paths_found=len(crawl.paths), params_found=len(params), forms_found=len(crawl.forms), js_found=len(crawl.scripts), api_routes_found=len(crawl.api_routes), evidence=json.dumps(crawl.stats, ensure_ascii=False))
        if not params:
            dashboard.event("WARNING", "No safe query parameters or GET inputs were discovered in the selected scope.")
        batch = batch_next_actions({"target": target, **crawl.stats, "max_pages": max_pages}, [p.to_dict() for p in params], no_findings_after_50=len(params) >= 50, limit=5)
        for item in batch.get("public_reasoning", []):
            dashboard.event("THINKING", str(item))
            dashboard.trace(str(item))
        tester = SafeVulnerabilityTester(target, parameters=params, threads=threads, delay=delay, timeout=request_timeout, scan_mode=scan_mode, dashboard=dashboard)
        results = tester.run()
        out = cai_output_dir(target)
        coverage = {
            "urls_total": len(crawl.urls),
            "urls_done": len(crawl.urls),
            "params_total": len(params),
            "params_safe_to_test": safe_count,
            "tests_total": results.get("summary", {}).get("tests_total", 0),
            "tests_done": results.get("summary", {}).get("tests_done", 0),
            "confirmed": len(results.get("confirmed_vulnerabilities", [])),
            "informational": len(results.get("informational", [])),
            "requests": results.get("summary", {}).get("requests", 0),
            "timeouts": results.get("summary", {}).get("timeouts", 0),
        }
        payload = {"target": target, "mode": "modern_safe_browser_scan", "render_js": render_js, "scan_mode": scan_mode, "runtime_ms": int((time.time() - started) * 1000), "coverage": coverage, "crawler": {"stats": crawl.stats, "result_file": str(out / "crawler-result.json")}, "ai_batch": batch, "confirmed_vulnerabilities": results.get("confirmed_vulnerabilities", []), "potential_findings": results.get("potential_findings", []), "informational": results.get("informational", []), "reports": {"modern_scan_json": str(out / "modern-scan-run.json"), "modern_scan_md": str(out / "modern-scan-run.md"), **results.get("reports", {})}, "safety": {"authorized_scope_required": True, "safe_canaries_only": scan_mode == "safe-active", "destructive_methods": False}}
        write_json(out / "modern-scan-run.json", payload)
        lines = ["# VulnScope Modern Safe Browser Scan", "", f"Target: `{target}`", f"Render JS: `{render_js}`", f"URLs: `{coverage['urls_total']}`", f"Parameters: `{coverage['params_total']}`", f"Tests: `{coverage['tests_done']}/{coverage['tests_total']}`", f"Requests: `{coverage['requests']}`", f"Timeouts: `{coverage['timeouts']}`", "", "## Confirmed"]
        if not payload["confirmed_vulnerabilities"]:
            lines.append("No confirmed issues were found by the selected safe checks.")
        for finding in payload["confirmed_vulnerabilities"]:
            lines.append(f"- **{finding.get('title')}** `{finding.get('severity')}` param=`{finding.get('parameter')}` evidence={finding.get('evidence')}")
        write_markdown(out / "modern-scan-run.md", lines)
        dashboard.report_paths.update(payload["reports"])
        dashboard.update(phase="Complete", phase_progress=100, action="Modern safe scan completed", evidence=json.dumps(coverage, ensure_ascii=False), requests=coverage["requests"], findings=len(payload["confirmed_vulnerabilities"]) + len(payload["potential_findings"]) + len(payload["informational"]), confirmed=len(payload["confirmed_vulnerabilities"]), informational=len(payload["informational"]))
        return payload
    except KeyboardInterrupt:
        dashboard.event("WARNING", "Interrupted by user; partial state written where available.")
        return {"target": target, "mode": "modern_safe_browser_scan", "interrupted": True, "runtime_ms": int((time.time() - started) * 1000)}
    finally:
        dashboard.stop(final=False)
        if final_dashboard:
            dashboard.show_final()


def run_loop(target: str, initial_scan_output: str = "", *, max_turns: int = 15, include_subdomains: bool = False, criticality: str = "normal", force: bool = False, live_dashboard: bool = False, final_dashboard: bool = True) -> dict[str, Any]:
    target = normalize_target(target)
    dashboard = LiveDashboard(target, max_turns=max_turns, enabled=final_dashboard, live_stream=live_dashboard)
    dashboard.start()
    out = cai_output_dir(target)
    current_output = initial_scan_output or "No prior output."
    completed: list[str] = []
    executed: list[dict[str, Any]] = []
    for turn in range(1, max_turns + 1):
        decision = think(current_output, {"target": target, "phase": "legacy_safe_react", "turn": turn, "plan": DEFAULT_PLAN, "completed": completed})
        action = str(decision.get("action") or "stop")
        dashboard.update(phase="Legacy ReAct", turn=turn, action=str(decision.get("analysis") or action), current_tool=action, probe_string="safe-planning")
        if action == "stop" or action in completed:
            break
        observation = {"action": action, "status": "completed", "summary": "legacy actuator not expanded in modern mode"}
        completed.append(action)
        executed.append(observation)
        current_output = json.dumps(observation)
    dashboard.stop(final=False)
    reports = dashboard.write_reports(out)
    payload = {"target": target, "mode": "legacy_safe_react_loop", "executed": executed, "reports": {"react_run_json": str(out / "react-run.json"), **reports}}
    write_json(out / "react-run.json", payload)
    if final_dashboard:
        dashboard.show_final()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope ReAct orchestration")
    parser.add_argument("--target", required=True)
    parser.add_argument("--modern-scan", action="store_true")
    parser.add_argument("--render-js", action="store_true", default=False)
    parser.add_argument("--max-pages", type=int, default=300)
    parser.add_argument("--min-pages-goal", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--scan-mode", choices=["passive", "safe-active"], default="passive")
    parser.add_argument("--no-robots", action="store_true")
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true", default=False)
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-final-dashboard", action="store_true")
    args = parser.parse_args()
    if args.modern_scan:
        payload = run_modern_scan(args.target, render_js=args.render_js, max_pages=args.max_pages, min_pages_goal=args.min_pages_goal, max_depth=args.max_depth, threads=args.threads, delay=args.delay, request_timeout=args.request_timeout, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, respect_robots=not args.no_robots, live_dashboard=bool(args.live_dashboard and not args.no_live_dashboard), final_dashboard=not args.no_final_dashboard)
    else:
        payload = run_loop(args.target, max_turns=args.max_turns, include_subdomains=args.include_subdomains, criticality=args.criticality, force=args.force, live_dashboard=bool(args.live_dashboard and not args.no_live_dashboard), final_dashboard=not args.no_final_dashboard)
    print(json.dumps({"status": "completed", "coverage": payload.get("coverage", {}), "reports": payload.get("reports", {})}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
