#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from core.ai_brain import AIBrain
from core.autonomous_scan_engine import AutonomousScanEngine, build_parser, parse_headers
from core.deepseek_autonomy_loop import DeepSeekAutonomyLoop


class DeepSeekDashboardEngine(AutonomousScanEngine):
    """Full dashboard engine with DeepSeek controlling the review loop."""

    def _safe_parameter_review(self) -> dict[str, Any]:
        self._dashboard(
            "DeepSeek Autonomous ReAct",
            "DeepSeek is choosing the next safe action from crawler state, parameters, previous observations, and approved tools",
            progress=76,
            agent="DeepSeekPlannerAgent",
            tool="deepseek_react_loop",
        )
        brain = AIBrain(model=self.ollama_model or "deepseek-local")
        loop = DeepSeekAutonomyLoop(
            target=self.target,
            state=self.state,
            crawler=self.crawler,
            tester=self.tester,
            dashboard=self.dashboard,
            dynamic_scheduler=self.dynamic_scheduler,
            brain=brain,
            max_turns=min(max(20, self.max_actions), 120),
            max_params=self.max_params,
            scan_mode=self.scan_mode,
        )
        self.react_summary = loop.run()
        if self.react_summary.get("summary_path"):
            self.extra_reports["deepseek_autonomy_summary"] = self.react_summary["summary_path"]
        if self.react_summary.get("markdown_path"):
            self.extra_reports["deepseek_autonomy_markdown"] = self.react_summary["markdown_path"]
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
