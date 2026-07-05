#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import py_compile
import sys
import time
from pathlib import Path
from typing import Any

EXCLUDE_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "tools"}
CRITICAL_MODULES = [
    "core.deepseek_cli",
    "core.deepseek_autonomy_loop",
    "core.deepseek_dashboard_engine",
    "core.safe_surface_engine",
    "core.surface_map",
    "core.registry_cleaner",
    "core.tool_suite_integrator",
    "core.autonomous_scan_engine",
    "core.phase_scheduler",
    "core.tool_manager",
    "core.tool_router",
    "core.live_dashboard",
    "core.ai_brain",
    "core.ai_tool_auto_configurator",
    "core.ai_tool_registry_repair",
]


def iter_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def compile_files(files: list[Path]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for path in files:
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            errors.append({"file": str(path), "error": str(exc)})
    return errors


def import_modules(modules: list[str]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for module in modules:
        try:
            importlib.import_module(module)
        except Exception as exc:
            errors.append({"module": module, "error": str(exc)})
    return errors


def registry_status() -> dict[str, Any]:
    try:
        from core.tool_registry import ToolRegistry
        registry = ToolRegistry()
        rows = registry.as_table_rows()
        ready = [row for row in rows if row.get("enabled") and row.get("approved_run") and row.get("has_run")]
        incomplete = [row for row in rows if not (row.get("enabled") and row.get("approved_run") and row.get("has_run"))]
        return {"ok": True, "total": len(rows), "ready": len(ready), "incomplete": len(incomplete), "incomplete_sample": incomplete[:25]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def dashboard_smoke() -> dict[str, Any]:
    try:
        from core.live_dashboard import LiveDashboard
        dash = LiveDashboard("http://example.test", enabled=False)
        dash.update(phase="Crawler v2", phase_progress=40, current_tool="crawler_v2", tool_status="completed", urls_found=3, params_found=1)
        dash.update(phase="Reporting", phase_progress=100, current_tool="report_generator", tool_status="completed")
        text = dash.render_text(color=False)
        final = dash.final_text(color=False)
        return {"ok": "queued means later phase" in text and "Tool Status:" in final, "render_len": len(text), "final_len": len(final)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VulnScope repository healthcheck")
    parser.add_argument("--json", default="reports/output/repo-healthcheck.json")
    args = parser.parse_args(argv)
    root = Path.cwd()
    files = iter_python_files(root)
    compile_errors = compile_files(files)
    import_errors = import_modules(CRITICAL_MODULES)
    registry = registry_status()
    dashboard = dashboard_smoke()
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_files_checked": len(files),
        "compile_errors": compile_errors,
        "import_errors": import_errors,
        "registry": registry,
        "dashboard": dashboard,
        "ok": not compile_errors and not import_errors and bool(dashboard.get("ok")),
    }
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
