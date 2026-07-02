#!/usr/bin/env python3
from __future__ import annotations

import json
import multiprocessing as mp
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Empty
from typing import Any

from cai_actuator_registry import ACTUATORS, call_actuator
from cai_error_handler import write_json, write_markdown

STATUS_VALUES = {"queued", "running", "completed", "failed", "skipped", "blocked_by_safety", "blocked_by_scope", "timed_out"}
MODE_RANK = {"passive": 0, "safe-active": 1, "lab": 2}
DEFAULT_TOOL_TIMEOUT = 20

CATEGORY_ACTUATOR = {
    "Scope and Authorization": "dependency_status",
    "URL Normalization": "target_profile",
    "Target Availability": "target_profile",
    "Safe Crawler": "passive_recon",
    "Security Headers": "target_profile",
    "Cookie Review": "target_profile",
    "TLS/HTTPS Review": "target_profile",
    "CORS Review": "target_profile",
    "CSP Review": "target_profile",
    "Robots/Sitemap Review": "passive_recon",
    "Security.txt Check": "passive_recon",
    "JavaScript Exposure Review": "passive_recon",
    "Source Map Check": "passive_recon",
    "Minimal Exposed File Check": "passive_recon",
    "Parameter Discovery": "input_inventory",
    "GET Form Discovery": "input_inventory",
    "Safe Canary Reflection Testing": "evidence_review",
    "Error Behavior Testing": "evidence_review",
    "Redirect Behavior Review": "hypothesis_matrix",
    "Broken Link Detection": "evidence_review",
    "Admin Route Exposure Review": "business_review",
    "Asset Inventory": "passive_recon",
    "Technology Fingerprinting": "target_profile",
    "API Route Discovery": "input_inventory",
    "Risk Scoring": "evidence_scoring",
    "Finding Validation": "prioritize",
    "Report Generation": "report",
}

CATEGORY_TOOLS: dict[str, list[str]] = {
    "Scope and Authorization": ["Authorization Consent Gate", "Scope Lock Validator", "Allowed Domain Resolver", "Excluded Path Filter"],
    "URL Normalization": ["Canonical URL Normalizer", "Scheme Enforcement Check", "Host Normalization Check", "Query Normalization Check"],
    "Target Availability": ["Root Availability Probe", "HEAD Capability Review", "Status Stability Monitor", "Retry After Observer"],
    "Safe Crawler": ["Internal Link Collector", "Depth Limited Crawler", "Robots Aware Crawler", "Duplicate URL Deduplicator"],
    "Security Headers": ["Content Security Policy Review", "HSTS Review", "Frame Options Review", "Content Type Options Review"],
    "Cookie Review": ["Set Cookie Inventory", "Secure Flag Review", "HttpOnly Flag Review", "SameSite Flag Review"],
    "TLS/HTTPS Review": ["HTTPS Scheme Review", "TLS Metadata Summary", "Certificate Hint Review"],
    "CORS Review": ["CORS Header Observer", "Credentialed CORS Review", "Wildcard Origin Review", "Origin Reflection Lead Review"],
    "CSP Review": ["CSP Presence Review", "CSP Weak Directive Review", "Inline Script CSP Review", "CSP Report URI Review"],
    "Robots/Sitemap Review": ["Robots TXT Fetcher", "Robots Path Classifier", "Sitemap URL Importer"],
    "Security.txt Check": ["Security TXT Fetcher", "Contact Policy Parser", "Disclosure Policy Parser"],
    "JavaScript Exposure Review": ["Script URL Collector", "Inline Script Route Extractor", "Client Secret Pattern Masker", "Dangerous Sink Static Review"],
    "Source Map Check": ["SourceMappingURL Detector", "Source Map HEAD Check", "Source Map Size Gate", "Source Map Route Extractor"],
    "Minimal Exposed File Check": ["Linked JSON Review", "Linked XML Review", "Public Text File Review"],
    "Parameter Discovery": ["Query Parameter Miner", "Hash Parameter Classifier", "Form Parameter Miner", "JavaScript Parameter Hint Miner"],
    "GET Form Discovery": ["GET Form Inventory", "Form Action Scope Gate", "Sensitive Form Skip Gate"],
    "Safe Canary Reflection Testing": ["Safe Canary Generator", "GET Parameter Canary Tester", "Reflection Context Classifier", "Canary Evidence Verifier"],
    "Error Behavior Testing": ["Baseline Response Profiler", "Canary Error Behavior Check", "Repeated 5xx Pause Guard", "Manual Review Error Lead"],
    "Redirect Behavior Review": ["Redirect Parameter Classifier", "Same Origin Redirect Observer", "External Redirect Blocker", "Redirect Manual Review Lead"],
    "Broken Link Detection": ["Discovered Link HEAD Check", "Broken Route Classifier", "Server Error Route Tracker"],
    "Admin Route Exposure Review": ["Discovered Admin Path Observer", "Auth Route Classifier", "Sensitive Path Skip Reporter"],
    "Asset Inventory": ["First Party Asset Inventory", "Third Party Asset Inventory", "Static File Type Classifier", "Asset Risk Summary"],
    "Technology Fingerprinting": ["Header Technology Hints", "HTML Framework Hints", "JavaScript Framework Hints", "CDN WAF Hint Review"],
    "API Route Discovery": ["API Path Pattern Extractor", "GraphQL Hint Observer", "JSON Endpoint Classifier", "Fetch XHR Route Extractor"],
    "Risk Scoring": ["Severity Distribution Calculator", "Confidence Score Aggregator", "Security Score Calculator", "Priority Sorter"],
    "Finding Validation": ["Evidence Presence Validator", "Deduplication Engine", "Finding Status Classifier", "False Positive Guard"],
    "Report Generation": ["Markdown Report Writer", "JSON Report Writer", "Tool Matrix Writer"],
}
SAFE_ACTIVE_CATEGORIES = {"Safe Canary Reflection Testing", "Error Behavior Testing", "Redirect Behavior Review"}


@dataclass
class ToolSpec:
    tool_id: str
    tool_name: str
    category: str
    description: str
    enabled: bool
    safety_level: str
    required_scan_mode: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    timeout: int
    rate_limit: str
    depends_on: list[str]
    run_function: str
    status: str = "queued"
    error_handler: str = "capture_error_continue_scan"


@dataclass
class ToolResult:
    tool_id: str
    tool_name: str
    category: str
    status: str
    runtime_ms: int
    output_count: int = 0
    actuator: str = ""
    message: str = ""
    evidence_summary: str = ""
    skipped_reason: str = ""
    error: str = ""
    cache_reused: bool = False


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")


def build_tool_registry(tool_timeout: int = DEFAULT_TOOL_TIMEOUT) -> list[ToolSpec]:
    timeout = max(3, int(tool_timeout or DEFAULT_TOOL_TIMEOUT))
    registry: list[ToolSpec] = []
    for category, tool_names in CATEGORY_TOOLS.items():
        actuator = CATEGORY_ACTUATOR[category]
        required_mode = "safe-active" if category in SAFE_ACTIVE_CATEGORIES else "passive"
        safety_level = "safe_active" if required_mode == "safe-active" else "passive"
        for name in tool_names:
            idx = len(registry) + 1
            registry.append(ToolSpec(
                tool_id=f"tool_{idx:03d}_{_slug(name)}",
                tool_name=name,
                category=category,
                description=f"Runs {name} through the safe VulnScope actuator layer for {category}.",
                enabled=True,
                safety_level=safety_level,
                required_scan_mode=required_mode,
                input_schema={"target": "authorized URL/domain", "scan_mode": "passive|safe-active|lab"},
                output_schema={"status": "tool execution state", "evidence_summary": "safe structured output summary"},
                timeout=timeout,
                rate_limit="shared_safe_pipeline_rate_limit",
                depends_on=[],
                run_function=actuator,
            ))
    if len(registry) != 100:
        raise RuntimeError(f"100-tool registry invariant failed: {len(registry)} tools generated")
    return registry


def _mode_allows(scan_mode: str, required_mode: str) -> bool:
    return MODE_RANK.get(scan_mode, 0) >= MODE_RANK.get(required_mode, 0)


def _is_error_result(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    status = str(result.get("status") or result.get("error") or "").lower()
    return status in {"handled_error", "error", "failed"} or "root_cause" in result


def _output_count(result: Any) -> int:
    if isinstance(result, dict):
        if "payload" in result and isinstance(result["payload"], dict):
            return len(result["payload"])
        return len(result)
    if isinstance(result, list):
        return len(result)
    return 1 if result is not None else 0


def _summary(result: Any, limit: int = 260) -> str:
    try:
        text = json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        text = str(result)
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def _actuator_worker(queue: Any, name: str, target: str, include_subdomains: bool, criticality: str) -> None:
    try:
        result = call_actuator(name, target=target, include_subdomains=include_subdomains, criticality=criticality)
        queue.put({"status": "completed", "result": result})
    except Exception as exc:
        queue.put({"status": "failed", "error": str(exc)[:1000]})


def _bounded_call_actuator(name: str, *, target: str, include_subdomains: bool, criticality: str, timeout: int) -> tuple[str, Any, str]:
    timeout = max(3, int(timeout or DEFAULT_TOOL_TIMEOUT))
    methods = mp.get_all_start_methods()
    ctx = mp.get_context("fork" if "fork" in methods else methods[0])
    queue: Any = ctx.Queue(maxsize=1)
    proc = ctx.Process(target=_actuator_worker, args=(queue, name, target, include_subdomains, criticality))
    proc.daemon = True
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive() and hasattr(proc, "kill"):
            proc.kill()
            proc.join(1)
        return "timed_out", None, f"{name} exceeded {timeout}s and was terminated; scan continued"
    try:
        payload = queue.get_nowait()
    except Empty:
        return "failed", None, f"{name} exited without returning output"
    except Exception as exc:
        return "failed", None, f"{name} output read failed: {exc}"
    status = str(payload.get("status") or "failed")
    if status == "completed":
        return "completed", payload.get("result"), ""
    return "failed", None, str(payload.get("error") or "unknown actuator error")[:1000]


class UltimateToolOrchestrator:
    """Deterministic 100-tool coordinator over the existing safe CAI/VulnScope actuator layer."""

    def __init__(self, target: str, *, scan_mode: str = "passive", include_subdomains: bool = False, criticality: str = "normal", dashboard: Any = None, tool_timeout: int = DEFAULT_TOOL_TIMEOUT) -> None:
        self.target = target
        self.scan_mode = scan_mode if scan_mode in MODE_RANK else "passive"
        self.include_subdomains = bool(include_subdomains)
        self.criticality = criticality
        self.dashboard = dashboard
        self.tool_timeout = max(3, int(tool_timeout or DEFAULT_TOOL_TIMEOUT))
        self.registry = build_tool_registry(self.tool_timeout)
        self.results: list[ToolResult] = []
        self.actuator_cache: dict[str, tuple[str, Any, str]] = {}

    def _emit(self, level: str, message: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event(level, message)
        else:
            print(f"[{level}] {message}", flush=True)

    def _update_dashboard(self, spec: ToolSpec, index: int, total: int, status: str, evidence: str = "") -> None:
        progress = int(index * 100 / max(1, total))
        if self.dashboard is None or not hasattr(self.dashboard, "update"):
            return
        self.dashboard.update(
            phase="100-Tool Orchestration",
            phase_progress=progress,
            phase_total=100,
            requests=index,
            action=f"{index}/{total} {spec.tool_name} → {status}",
            probe_string=f"safe-orchestrator:{spec.tool_id}",
            hypothesis=f"{spec.category} via {spec.run_function}",
            evidence=evidence or "Structured safe tool status event emitted",
            safety_status=f"100-tool registry • hard timeout {self.tool_timeout}s • target data modification disabled",
        )

    def _run_one(self, spec: ToolSpec, index: int, total: int) -> ToolResult:
        started = time.time()
        if not spec.enabled:
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "skipped", 0, skipped_reason="tool disabled", actuator=spec.run_function)
        if not _mode_allows(self.scan_mode, spec.required_scan_mode):
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "skipped", 0, skipped_reason=f"requires {spec.required_scan_mode}; current mode is {self.scan_mode}", actuator=spec.run_function)
        if spec.run_function not in ACTUATORS:
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "failed", 0, error=f"unregistered actuator {spec.run_function}", actuator=spec.run_function)

        self._update_dashboard(spec, index, total, "running")
        self._emit("INFO", f"{index}/{total} {spec.tool_name}: running through {spec.run_function} timeout={spec.timeout}s")
        cache_reused = spec.run_function in self.actuator_cache
        if cache_reused:
            call_status, raw, call_error = self.actuator_cache[spec.run_function]
        else:
            call_status, raw, call_error = _bounded_call_actuator(
                spec.run_function,
                target=self.target,
                include_subdomains=self.include_subdomains,
                criticality=self.criticality,
                timeout=spec.timeout,
            )
            self.actuator_cache[spec.run_function] = (call_status, raw, call_error)

        runtime_ms = int((time.time() - started) * 1000)
        if call_status == "timed_out":
            self._emit("WARNING", f"{index}/{total} {spec.tool_name}: timed out after {spec.timeout}s; moving to next tool")
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "timed_out", runtime_ms, actuator=spec.run_function, error=call_error, cache_reused=cache_reused)
        if call_status == "failed":
            self._emit("WARNING", f"{index}/{total} {spec.tool_name}: failed safely and scan continued")
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "failed", runtime_ms, actuator=spec.run_function, error=call_error, cache_reused=cache_reused)
        if _is_error_result(raw):
            self._emit("WARNING", f"{index}/{total} {spec.tool_name}: actuator returned handled error")
            return ToolResult(spec.tool_id, spec.tool_name, spec.category, "failed", runtime_ms, output_count=_output_count(raw), actuator=spec.run_function, error=_summary(raw), cache_reused=cache_reused)

        result = ToolResult(spec.tool_id, spec.tool_name, spec.category, "completed", runtime_ms, output_count=_output_count(raw), actuator=spec.run_function, message="completed using safe integrated actuator output", evidence_summary=_summary(raw), cache_reused=cache_reused)
        self._emit("SUCCESS", f"{index}/{total} {spec.tool_name}: completed")
        self._update_dashboard(spec, index, total, "completed", result.evidence_summary)
        return result

    def run(self) -> dict[str, Any]:
        total = len(self.registry)
        self._emit("INFO", f"100-tool orchestrator started in {self.scan_mode} mode with {self.tool_timeout}s hard timeout per actuator")
        for index, spec in enumerate(self.registry, 1):
            result = self._run_one(spec, index, total)
            self.results.append(result)
            if result.status == "skipped":
                self._emit("INFO", f"{index}/{total} {spec.tool_name}: skipped ({result.skipped_reason})")
            elif result.status in {"failed", "timed_out"}:
                self._emit("WARNING", f"{index}/{total} {spec.tool_name}: {result.status}; scan continued")
            self._update_dashboard(spec, index, total, result.status, result.evidence_summary or result.error or result.skipped_reason)
        self._emit("SUCCESS", "100-tool orchestrator completed")
        return self.payload()

    def payload(self) -> dict[str, Any]:
        counts = {status: 0 for status in sorted(STATUS_VALUES)}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "tool_timeout": self.tool_timeout,
            "generated_at": time.time(),
            "tool_count": len(self.registry),
            "status_counts": counts,
            "registry": [asdict(item) for item in self.registry],
            "results": [asdict(item) for item in self.results],
            "actuator_cache_keys": sorted(self.actuator_cache.keys()),
            "safety": {"allowlisted_actuators_only": True, "hard_timeout_per_actuator": True, "target_data_modification": False, "skipped_tools_not_marked_completed": True, "failed_tools_do_not_create_findings": True, "timed_out_tools_do_not_block_scan": True},
        }

    def write_reports(self, out: Path) -> dict[str, str]:
        out.mkdir(parents=True, exist_ok=True)
        payload = self.payload()
        matrix_json = out / "tool-matrix.json"
        matrix_md = out / "tool-matrix.md"
        registry_json = out / "tool-registry-100.json"
        write_json(matrix_json, payload)
        write_json(registry_json, payload["registry"])
        lines = ["# VulnScope 100-Tool Orchestration Matrix", "", f"Target: `{self.target}`", f"Scan mode: `{self.scan_mode}`", f"Tool timeout: `{self.tool_timeout}s`", f"Total tools: `{payload['tool_count']}`", "", "## Status counts", ""]
        for key, value in payload["status_counts"].items():
            lines.append(f"- `{key}`: `{value}`")
        lines += ["", "## Tool results", ""]
        for result in payload["results"]:
            lines.append(f"- `{result['tool_id']}` **{result['tool_name']}** — category=`{result['category']}` status=`{result['status']}` actuator=`{result['actuator']}` runtime_ms=`{result['runtime_ms']}` output_count=`{result['output_count']}` cache_reused=`{result['cache_reused']}`")
            if result.get("skipped_reason"):
                lines.append(f"  - skipped_reason: {result['skipped_reason']}")
            if result.get("error"):
                lines.append(f"  - error: {result['error']}")
        write_markdown(matrix_md, lines)
        return {"tool_matrix_json": str(matrix_json), "tool_matrix_md": str(matrix_md), "tool_registry_100_json": str(registry_json)}


def _print_summary(payload: dict[str, Any], reports: dict[str, str]) -> None:
    counts = payload.get("status_counts", {})
    print("\n" + "=" * 80)
    print("VULNSCOPE 100-TOOL ORCHESTRATION MATRIX — FINAL")
    print("=" * 80)
    print(f"Target: {payload.get('target')}")
    print(f"Scan mode: {payload.get('scan_mode')}")
    print(f"Tool timeout: {payload.get('tool_timeout')}s")
    print(f"Total tools: {payload.get('tool_count')}")
    print(f"Completed: {counts.get('completed', 0)}")
    print(f"Skipped: {counts.get('skipped', 0)}")
    print(f"Failed: {counts.get('failed', 0)}")
    print(f"Timed out: {counts.get('timed_out', 0)}")
    print(f"Blocked by scope: {counts.get('blocked_by_scope', 0)}")
    print(f"Blocked by safety: {counts.get('blocked_by_safety', 0)}")
    print("Reports:")
    for name, path in reports.items():
        print(f"- {name}: {path}")
    print("=" * 80)


def main() -> int:
    import argparse
    from cai_scope_guard import cai_output_dir, normalize_target
    from core.live_dashboard import LiveDashboard

    parser = argparse.ArgumentParser(description="VulnScope deterministic 100-tool safe orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-mode", default="passive", choices=["passive", "safe-active", "lab"])
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--tool-timeout", type=int, default=DEFAULT_TOOL_TIMEOUT)
    parser.add_argument("--no-live-dashboard", action="store_true")
    args = parser.parse_args()

    target = normalize_target(args.target)
    dashboard = LiveDashboard(target, max_turns=100, enabled=True, live_stream=not args.no_live_dashboard)
    dashboard.start()
    payload: dict[str, Any] = {}
    orchestrator: UltimateToolOrchestrator | None = None
    try:
        dashboard.event("INFO", f"100-tool matrix started. Hard timeout={args.tool_timeout}s per actuator.")
        orchestrator = UltimateToolOrchestrator(target, scan_mode=args.scan_mode, include_subdomains=args.include_subdomains, criticality=args.criticality, dashboard=dashboard, tool_timeout=args.tool_timeout)
        payload = orchestrator.run()
    finally:
        dashboard.stop(final=False)
    if orchestrator is None:
        raise SystemExit("orchestrator failed to initialize")
    reports = orchestrator.write_reports(cai_output_dir(target))
    dashboard.report_paths = dict(reports)
    _print_summary(payload, reports)
    print(json.dumps({"status": "completed", "reports": reports, "status_counts": payload.get("status_counts", {})}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
