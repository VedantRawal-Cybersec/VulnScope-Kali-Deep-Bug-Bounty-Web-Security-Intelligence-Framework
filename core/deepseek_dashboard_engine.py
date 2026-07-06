#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from core.ai_brain import AIBrain
from core.autonomous_scan_engine import AutonomousScanEngine, build_parser, parse_headers
from core.deepseek_autonomy_loop import DeepSeekAutonomyLoop
from core.safe_surface_engine import SafeSurfaceEngine


class DeepSeekDashboardEngine(AutonomousScanEngine):
    """Full dashboard engine with deterministic mapping before AI control."""

    def _safe_parameter_review(self) -> dict[str, Any]:
        self._dashboard("Surface Mapping", "Mapping URLs, forms, parameters, scripts, and checks", progress=74, agent="SafeSurfaceEngine", tool="safe_surface_engine")
        surface = SafeSurfaceEngine(state=self.state, client=self.client, tester=self.tester, dashboard=self.dashboard, max_pages=self.max_pages, max_depth=self.max_depth, max_params=self.max_params, mode=self.scan_mode, include_subdomains=self.include_subdomains).run_all()
        self.extra_reports.update(surface.get("reports", {}))
        self.state.add_event("INFO", "surface mapping completed", summary=surface)
        self.state.save()

        self._dashboard("DeepSeek Autonomous ReAct", "DeepSeek is choosing the next action from mapped scan state", progress=80, agent="DeepSeekPlannerAgent", tool="deepseek_react_loop")
        brain = AIBrain(model=self.ollama_model or "deepseek-local")
        loop = DeepSeekAutonomyLoop(target=self.target, state=self.state, crawler=self.crawler, tester=self.tester, dashboard=self.dashboard, dynamic_scheduler=self.dynamic_scheduler, brain=brain, max_turns=min(max(20, self.max_actions), 120), max_params=self.max_params, scan_mode=self.scan_mode)
        self.react_summary = loop.run()
        self.react_summary["surface"] = surface
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
