#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

from core.live_dashboard import LiveDashboard
from core.react_loop import run_loop
from core.tool_orchestrator import UltimateToolOrchestrator


def _print_matrix_summary(payload: dict[str, Any], reports: dict[str, str]) -> None:
    counts = payload.get("status_counts", {})
    total = payload.get("tool_count", 0)
    print("\n" + "=" * 80)
    print("VULNSCOPE 100-TOOL ORCHESTRATION MATRIX")
    print("=" * 80)
    print(f"Total tools wired: {total}")
    print(f"Completed: {counts.get('completed', 0)}")
    print(f"Skipped: {counts.get('skipped', 0)}")
    print(f"Failed: {counts.get('failed', 0)}")
    print(f"Blocked by safety: {counts.get('blocked_by_safety', 0)}")
    print(f"Scan mode: {payload.get('scan_mode', 'passive')}")
    print("Report files:")
    for name, path in reports.items():
        print(f"- {name}: {path}")
    print("=" * 80)


def run_ultimate(
    target: str,
    *,
    max_turns: int = 15,
    include_subdomains: bool = False,
    criticality: str = "normal",
    scan_mode: str = "passive",
    force: bool = False,
    live_dashboard: bool = False,
    final_dashboard: bool = True,
) -> dict[str, Any]:
    target = normalize_target(target)
    out = cai_output_dir(target)
    started = time.time()

    orchestrator_dashboard = LiveDashboard(
        target,
        max_turns=100,
        enabled=True,
        live_stream=live_dashboard,
    )
    orchestrator_dashboard.start()
    orchestrator_dashboard.event("INFO", f"Starting 100-tool orchestrator in {scan_mode} mode.")
    orchestrator = UltimateToolOrchestrator(
        target,
        scan_mode=scan_mode,
        include_subdomains=include_subdomains,
        criticality=criticality,
        dashboard=orchestrator_dashboard,
    )
    orchestrator_payload = orchestrator.run()
    orchestrator_dashboard.stop(final=False)
    orchestrator_reports = orchestrator.write_reports(out)
    orchestrator_dashboard.report_paths = dict(orchestrator_reports)
    _print_matrix_summary(orchestrator_payload, orchestrator_reports)

    initial_output = json.dumps(
        {
            "hundred_tool_orchestrator": True,
            "tool_count": orchestrator_payload.get("tool_count"),
            "status_counts": orchestrator_payload.get("status_counts"),
            "actuator_cache_keys": orchestrator_payload.get("actuator_cache_keys"),
            "reports": orchestrator_reports,
        },
        indent=2,
        ensure_ascii=False,
    )

    react_payload = run_loop(
        target,
        initial_scan_output=initial_output,
        max_turns=max_turns,
        include_subdomains=include_subdomains,
        criticality=criticality,
        force=force,
        live_dashboard=live_dashboard,
        final_dashboard=final_dashboard,
    )
    reports = {**orchestrator_reports, **react_payload.get("reports", {})}
    payload = {
        "target": target,
        "generated_at": time.time(),
        "runtime_ms": int((time.time() - started) * 1000),
        "mode": "ultimate_100_tool_orchestrated_safe_scan",
        "scan_mode": scan_mode,
        "orchestrator": orchestrator_payload,
        "react": react_payload,
        "reports": {
            "ultimate_run_json": str(out / "ultimate-run.json"),
            "ultimate_run_md": str(out / "ultimate-run.md"),
            **reports,
        },
        "safety": {
            "allowlisted_actuators_only": True,
            "hundred_tool_orchestrator": True,
            "skipped_tools_not_marked_completed": True,
            "failed_tools_do_not_create_findings": True,
            "target_data_modification": False,
            "website_dashboard": False,
        },
    }
    write_json(out / "ultimate-run.json", payload)
    lines = [
        "# VulnScope Ultimate 100-Tool Orchestrated Run",
        "",
        f"Target: `{target}`",
        f"Scan mode: `{scan_mode}`",
        f"Runtime ms: `{payload['runtime_ms']}`",
        "",
        "## 100-tool matrix",
        "",
        f"Tool count: `{orchestrator_payload.get('tool_count')}`",
        f"Status counts: `{json.dumps(orchestrator_payload.get('status_counts', {}), ensure_ascii=False)}`",
        "",
        "## Reports",
    ]
    for name, path in payload["reports"].items():
        lines.append(f"- `{name}`: `{path}`")
    write_markdown(out / "ultimate-run.md", lines)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope ultimate safe 100-tool orchestrated loop")
    parser.add_argument("--target", required=True)
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--scan-mode", default="passive", choices=["passive", "safe-active", "lab"])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--no-final-dashboard", action="store_true")
    args = parser.parse_args()
    payload = run_ultimate(
        args.target,
        max_turns=args.max_turns,
        include_subdomains=args.include_subdomains,
        criticality=args.criticality,
        scan_mode=args.scan_mode,
        force=args.force,
        live_dashboard=bool(args.live_dashboard and not args.no_live_dashboard),
        final_dashboard=not args.no_final_dashboard,
    )
    print(json.dumps({"status": "completed", "reports": payload.get("reports", {})}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
