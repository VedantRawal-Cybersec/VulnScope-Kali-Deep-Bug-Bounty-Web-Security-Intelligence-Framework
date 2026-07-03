#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from urllib.parse import urlparse

from core.autonomous_scan_engine import AutonomousScanEngine, find_param_for_test, parse_headers
from core.cai_react_controller import CAIReActController
from core.test_queue import TestQueueBuilder, test_requires_network

VERSION = "1.11.1-cai-full-llm-react-runtime"


def run_runtime(args: argparse.Namespace) -> dict:
    os.environ["VULNSCOPE_FULL_LLM_BEHAVIOR"] = "0" if args.no_full_llm else "1"
    os.environ["VULNSCOPE_LLM_ENABLED"] = "0" if args.no_llm else "1"
    health_mode = args.llm_health_mode
    if not args.no_full_llm and health_mode == "tags-only":
        health_mode = "full"

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
        max_actions=args.max_turns,
        resume=args.resume,
        browser=args.browser or args.render_js,
        live_dashboard=not args.no_live_dashboard,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        ollama_timeout=args.ollama_timeout,
        llm_health_mode=health_mode,
    )

    started = time.time()
    engine.dashboard.start()
    controller = CAIReActController(llm=engine.llm, scan_mode=engine.scan_mode)
    classification_done = 0
    safe_done = 0
    skipped_budget = 0
    try:
        engine.bootstrap()
        engine._set_budget_phase("testing", engine.total_request_budget)
        start_requests = int(engine.state.stats.get("requests", 0))
        engine.handoffs.handoff("ParameterDiscoveryAgent", "OllamaReasoningAgent", phase="CAI ReAct", message="starting Think Act Observe loop", progress_percent=42)
        engine.tool_router.started("test_queue_builder", "building explicit test queue")
        builder = TestQueueBuilder(state=engine.state, scan_mode=engine.scan_mode, max_params=engine.max_params)
        summary = builder.build()
        engine.tool_router.completed("test_queue_builder", output_count=summary.tests_created, reason=json.dumps(summary.to_dict(), ensure_ascii=False))
        tests = builder.ordered_tests()
        if tests:
            engine.tool_router.started("classification_review", "ReAct controlled classification checks")
            if engine.scan_mode in {"safe-active", "lab"}:
                engine.tool_router.started("safe_canary_reflection", "ReAct controlled safe checks")
        else:
            engine.tool_router.skipped("classification_review", "no queued tests")
            engine.tool_router.skipped("safe_canary_reflection", "no queued tests")

        turns = 0
        while turns < args.max_turns:
            queued = [item for item in tests if item.status == "queued"]
            if not queued:
                break
            turns += 1
            progress = 45 + int(turns * 40 / max(1, args.max_turns))
            decision = controller.decide(state=engine.state, tests=tests, turn=turns, max_turns=args.max_turns, budget_remaining=engine.client.budget_remaining())
            engine.reasoning.publish(
                agent="OllamaReasoningAgent" if decision.source == "ollama" else "DeterministicReActAgent",
                observation=f"turn={turns} coverage={engine.state.coverage()}",
                hypothesis=decision.public_reasoning,
                decision=f"{decision.action}:{decision.tool}",
                selected_tool=decision.tool,
                safety=decision.safety,
                evidence_summary=decision.message,
                next_action=decision.action,
                progress_percent=progress,
            )
            engine.dashboard.update(current_agent="OllamaReasoningAgent" if decision.source == "ollama" else "DeterministicReActAgent", current_tool=decision.tool, decision=decision.action, action=decision.public_reasoning, phase="CAI ReAct", phase_progress=progress)
            if decision.action in {"report", "stop"}:
                break
            test = next((item for item in queued if item.test_id == decision.test_id), queued[0])
            param = find_param_for_test(engine.state, test)
            if param is None:
                test.status = "skipped"
                test.error = "parameter missing"
                engine.state.add_test(test)
                controller.observe(decision, status="skipped", output=test.error)
                continue
            if test_requires_network(test.test_name) and engine.client.budget_remaining() <= 0:
                test.status = "skipped"
                test.error = "test request budget exhausted"
                test.finished_at = time.time()
                engine.state.add_test(test)
                skipped_budget += 1
                controller.observe(decision, status="skipped", output=test.error)
                continue
            engine.handoffs.handoff("OllamaReasoningAgent", "SafeCanaryTestingAgent", phase="CAI ReAct", message=f"executing {test.test_name}", target_url=param.url, path=urlparse(param.url).path or "/", parameter=param.name, progress_percent=progress)
            outcome = engine.tester.run_test(param, test.test_name)
            if test.test_name == "classification_review":
                classification_done += 1
            else:
                safe_done += 1
            controller.observe(decision, status=outcome.status, output=outcome.message, evidence_id=str(outcome.evidence_id or ""))

        engine.tool_router.completed("classification_review", output_count=classification_done, reason=f"completed {classification_done} ReAct classification checks")
        if engine.scan_mode in {"safe-active", "lab"}:
            if safe_done:
                engine.tool_router.completed("safe_canary_reflection", output_count=safe_done, reason=f"completed {safe_done} ReAct safe checks")
            else:
                engine.tool_router.skipped("safe_canary_reflection", "no safe checks completed")
        else:
            engine.tool_router.blocked("safe_canary_reflection", "passive mode")
        engine.state.stats["cai_full_llm_runtime"] = {
            "version": VERSION,
            "turns": turns,
            "classification_done": classification_done,
            "safe_done": safe_done,
            "skipped_budget": skipped_budget,
            "test_requests_used": int(engine.state.stats.get("requests", 0)) - start_requests,
        }
        controller.write_state(engine.state)
        engine.memory.update_from_state(engine.state)
        reports = engine.write_reports()
        engine._dashboard("Final Dashboard", "CAI full LLM ReAct runtime completed", progress=100, evidence=engine._coverage_text(), agent="ReportAgent", tool="report_generator")
        return {"status": "completed", "version": VERSION, "target": engine.target, "coverage": engine.state.coverage(), "cai_react": engine.state.stats.get("cai_react_controller", {}), "reports": reports, "runtime_ms": int((time.time() - started) * 1000)}
    except KeyboardInterrupt:
        engine.state.add_event("WARNING", "interrupted by user")
        controller.write_state(engine.state)
        reports = engine.write_reports()
        return {"status": "interrupted", "version": VERSION, "target": engine.target, "coverage": engine.state.coverage(), "reports": reports}
    finally:
        engine.dashboard.stop(final=False)
        engine.state.save()


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope CAI full LLM ReAct runtime")
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
    parser.add_argument("--max-turns", type=int, default=80)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--render-js", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-full-llm", action="store_true")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/chat"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    parser.add_argument("--ollama-timeout", type=int, default=int(os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "60")))
    parser.add_argument("--llm-health-mode", choices=["tags-only", "full", "disabled"], default=os.getenv("VULNSCOPE_LLM_HEALTH_MODE", "full"))
    args = parser.parse_args()
    payload = run_runtime(args)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("status") in {"completed", "interrupted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
