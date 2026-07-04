#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"

VERSION = "1.17.4-classic-phase-stable"
SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
SENSITIVE_PATTERNS = [re.compile(r"(?i)(api[_-]?key|token|secret|authorization|cookie|session|password)=([^\s&;]+)")]


@dataclass
class LiveSnapshot:
    target: str
    scan_id: str = field(default_factory=lambda: "scan_" + uuid.uuid4().hex[:10])
    mode: str = "passive"
    authorization_status: str = "confirmed"
    ollama_status: str = "checking"
    phase: str = "Starting"
    previous_phase: str = "—"
    phase_progress: int = 0
    phase_total: int = 100
    phase_started_at: float = field(default_factory=time.time)
    last_update_at: float = field(default_factory=time.time)
    spinner_index: int = 0
    turn: int = 0
    max_turns: int = 0
    findings: int = 0
    requests: int = 0
    action: str = "Initializing autonomous workflow"
    current_agent: str = "SupervisorAgent"
    current_tool: str = "initializer"
    handoff: str = "—"
    decision: str = "—"
    domain: str = "—"
    endpoint: str = "—"
    request_line: str = "GET /"
    method: str = "GET"
    path: str = "/"
    parameters: str = "No safe query parameters or GET inputs discovered yet"
    probe_string: str = "—"
    response_code: str = "—"
    response_time_ms: str = "—"
    hypothesis: str = "—"
    evidence: str = "—"
    safety_status: str = "Scope locked • consent-gated • same-scope • safe-active"
    latest_status: str = "waiting"
    urls_found: int = 0
    paths_found: int = 0
    params_found: int = 0
    forms_found: int = 0
    js_found: int = 0
    api_routes_found: int = 0
    tools_total: int = 0
    tools_running: int = 0
    tools_completed: int = 0
    tools_failed: int = 0
    tools_skipped: int = 0
    tools_blocked: int = 0
    tools_inactive: int = 0
    tools_not_ready: int = 0
    confirmed: int = 0
    potential: int = 0
    informational: int = 0
    latest_finding: str = "—"
    started_at: float = field(default_factory=time.time)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def _colorize(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _clean(value: Any, limit: int = 120) -> str:
    text = str(value if value is not None else "—")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip() or "—"
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    return text[: max(0, limit - 1)] + "…" if len(text) > limit else text


def _clean_multiline(value: Any, limit: int = 1200) -> str:
    text = str(value if value is not None else "—").replace("\r", "")
    lines = [_clean(line, 220) for line in text.splitlines()]
    text = "\n".join(lines).strip() or "—"
    return text[: max(0, limit - 1)] + "…" if len(text) > limit else text


def target_components(target: str) -> dict[str, str]:
    raw = str(target or "").strip()
    normalized = raw if "://" in raw else "https://" + raw
    parsed = urlparse(normalized)
    domain = (parsed.hostname or parsed.netloc or raw).split(":")[0].lower().strip() or "—"
    path = parsed.path or "/"
    query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
    request_line = f"GET {path}" + (("?" + parsed.query) if parsed.query else "")
    return {"target": normalized, "domain": domain, "endpoint": normalized, "request_line": request_line, "path": path, "parameters": query, "method": "GET"}


def _pad(text: str, width: int) -> str:
    raw = _strip_ansi(text)
    if len(raw) > width:
        raw = raw[: max(0, width - 1)] + "…"
        text = raw
    return text + (" " * max(0, width - len(raw)))


def _box(title: str, lines: list[str], *, color: str = CYAN, enabled: bool = True, width: int = 95) -> list[str]:
    inner = width - 2
    out = [_colorize("┌─ " + title + " " + "─" * max(0, inner - len(title) - 3) + "┐", color, enabled)]
    for line in lines:
        out.append(_colorize("│", color, enabled) + " " + _pad(line, inner - 2) + " " + _colorize("│", color, enabled))
    out.append(_colorize("└" + "─" * inner + "┘", color, enabled))
    return out


class LiveDashboard:
    """Classic VulnScope CLI dashboard with fixed phase/timer/tool state.

    The visual structure intentionally matches the original CLI dashboard: Agent
    Trace, Tool Matrix, Live Reasoning, Current Context, Live Log, and footer.
    """

    TOOL_ORDER = [
        "crawler_v2",
        "browser_crawler",
        "parameter_inventory",
        "header_analyzer",
        "cookie_analyzer",
        "metadata_checker",
        "js_route_review",
        "classification_review",
        "safe_canary_reflection",
        "deep_scan_phase_pack",
        "external_tool_readiness",
        "unified_research_orchestrator",
        "report_generator",
        "llm_public_reasoning",
        "llm_evidence_validator",
    ]

    def __init__(self, target: str, *, max_turns: int = 0, enabled: bool = True, live_stream: bool = False, refresh_interval: float = 0.5, interactive: bool | None = None) -> None:
        parts = target_components(target)
        self.snapshot = LiveSnapshot(
            target=_clean(parts["target"], 180),
            max_turns=max_turns,
            domain=_clean(parts["domain"], 100),
            endpoint=_clean(parts["endpoint"], 180),
            request_line=_clean(parts["request_line"], 180),
            path=_clean(parts["path"], 140),
            parameters=_clean(parts["parameters"], 180),
            method=parts.get("method", "GET"),
        )
        self.enabled = bool(enabled) and os.getenv("VULNSCOPE_NO_CLI_DASHBOARD", "0") != "1"
        self.live_stream = bool(live_stream) and os.getenv("VULNSCOPE_NO_LIVE_DASHBOARD", "0") != "1"
        self.interactive = sys.stdout.isatty() if interactive is None else bool(interactive)
        self.refresh_interval = max(float(refresh_interval), 0.2)
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.traces: list[str] = []
        self.finding_details: list[dict[str, Any]] = []
        self.max_events = 10
        self.running = False
        self.thread: threading.Thread | None = None
        self.report_paths: dict[str, str] = {}
        self._alt_screen = False
        self._last_height = 0
        self._last_render_at = 0.0

    def start(self) -> None:
        if not self.enabled or not self.live_stream:
            return
        self.running = True
        self.snapshot.started_at = time.time()
        self.snapshot.phase_started_at = self.snapshot.started_at
        if self.interactive:
            sys.stdout.write("\033[?1049h\033[?25l\033[H\033[J")
            sys.stdout.flush()
            self._alt_screen = True
            self.thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self.thread.start()
        else:
            print("[vulnscope] live dashboard active; non-interactive mode will print important events", flush=True)

    def _refresh_loop(self) -> None:
        while self.running:
            self.draw(final=False)
            time.sleep(self.refresh_interval)

    def stop(self, *, final: bool = False) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        if self._alt_screen:
            sys.stdout.write("\033[?25h\033[?1049l")
            sys.stdout.flush()
            self._alt_screen = False
        if final and self.enabled:
            self.show_final()

    def update(self, **kwargs: Any) -> None:
        now = time.time()
        with self.lock:
            endpoint_value = kwargs.get("endpoint") or kwargs.get("target_url") or kwargs.get("url")
            if endpoint_value and not any(k in kwargs for k in ("domain", "request_line", "path", "parameters")):
                parts = target_components(str(endpoint_value))
                kwargs.setdefault("domain", parts["domain"])
                kwargs.setdefault("endpoint", parts["endpoint"])
                kwargs.setdefault("request_line", parts["request_line"])
                kwargs.setdefault("path", parts["path"])
                kwargs.setdefault("parameters", parts["parameters"])
            new_phase = str(kwargs.get("phase", self.snapshot.phase))
            if new_phase and new_phase != self.snapshot.phase:
                self.snapshot.previous_phase = self.snapshot.phase
                self.snapshot.phase = _clean(new_phase, 160)
                self.snapshot.phase_started_at = now
                self.snapshot.spinner_index = 0
                self.snapshot.latest_status = "phase_started"
                self.events.append(f"[{time.strftime('%H:%M:%S')}] 🔁 Phase changed: {self.snapshot.previous_phase} → {self.snapshot.phase}")
                self.events = self.events[-self.max_events:]
            integer_fields = {"phase_progress", "phase_total", "turn", "max_turns", "findings", "requests", "urls_found", "paths_found", "params_found", "forms_found", "js_found", "api_routes_found", "tools_total", "tools_running", "tools_completed", "tools_failed", "tools_skipped", "tools_blocked", "tools_inactive", "tools_not_ready", "confirmed", "potential", "informational"}
            for key, value in kwargs.items():
                if key == "phase":
                    continue
                if hasattr(self.snapshot, key):
                    if key in integer_fields:
                        try:
                            setattr(self.snapshot, key, int(value))
                        except Exception:
                            setattr(self.snapshot, key, 0)
                    else:
                        setattr(self.snapshot, key, _clean(value, 260))
            self.snapshot.last_update_at = now
            self.snapshot.spinner_index = (self.snapshot.spinner_index + 1) % len(SPINNER)

    def event(self, level: str, message: str) -> None:
        level = str(level or "INFO").upper()
        icon = {"SUCCESS": "✅", "INFO": "ℹ️ ", "WARNING": "⚠️ ", "BLOCKED": "🛡️ ", "FINDING": "🔥", "THINKING": "🧠", "HANDOFF": "🔁", "ERROR": "❌"}.get(level, "• ")
        rendered = f"[{time.strftime('%H:%M:%S')}] {icon} {_clean(message, 240)}"
        with self.lock:
            self.events.append(rendered)
            self.events = self.events[-self.max_events:]
            self.snapshot.latest_status = level.lower()
            self.snapshot.last_update_at = time.time()
            self.snapshot.spinner_index = (self.snapshot.spinner_index + 1) % len(SPINNER)
        if self.enabled and self.live_stream and not self.interactive and level in {"WARNING", "BLOCKED", "FINDING", "SUCCESS", "ERROR"}:
            print(_strip_ansi(rendered), flush=True)

    def trace(self, message: str) -> None:
        with self.lock:
            self.traces.append(f"{time.strftime('%H:%M:%S')} {_clean(message, 240)}")
            self.traces = self.traces[-8:]

    def add_finding(self, finding_type: str, description: str, severity: str = "INFO", *, url: str = "", parameter: str = "", test_string: str = "", evidence: str = "", cvss: str = "N/A", confidence: str = "N/A", reproduction: str = "", confirmation: str = "review_lead") -> dict[str, Any]:
        severity = _clean(severity or "INFO", 30).upper()
        confirmation = _clean(confirmation or "review_lead", 40).lower()
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            finding = {
                "type": _clean(finding_type or "Security Review Lead", 140),
                "severity": severity,
                "description": _clean(description or "Evidence requires analyst review.", 500),
                "url": _clean(url or snap.endpoint, 260),
                "domain": _clean(snap.domain, 120),
                "request_line": _clean(snap.request_line, 240),
                "path": _clean(snap.path, 180),
                "parameter": _clean(parameter or snap.parameters, 220),
                "test_string": _clean(test_string or snap.probe_string, 220),
                "evidence": _clean(evidence or snap.evidence, 900),
                "cvss": _clean(cvss, 80),
                "confidence": _clean(confidence, 80),
                "reproduction": _clean_multiline(reproduction or "Review generated evidence and validate only inside the authorized scope."),
                "confirmation": confirmation,
                "recorded_at": time.time(),
            }
            self.finding_details.append(finding)
            self.snapshot.findings = len(self.finding_details)
            self.snapshot.latest_finding = f"{severity} {finding['type']}"
            if confirmation == "confirmed":
                self.snapshot.confirmed += 1
            elif confirmation in {"potential", "review_lead"}:
                self.snapshot.potential += 1
            else:
                self.snapshot.informational += 1
            self.events.append(f"[{time.strftime('%H:%M:%S')}] 🔥 [{severity}] {finding['type']}: {finding['description']}")
            self.events = self.events[-self.max_events:]
        return finding

    def finding_count(self) -> int:
        with self.lock:
            return len(self.finding_details)

    def set_target_detail(self, target: str, *, probe_string: str = "—") -> None:
        parts = target_components(target)
        self.update(domain=parts["domain"], endpoint=parts["endpoint"], request_line=parts["request_line"], path=parts["path"], parameters=parts["parameters"], probe_string=probe_string)

    def _elapsed(self) -> str:
        seconds = max(0, int(time.time() - self.snapshot.started_at))
        return f"{seconds // 60:02d}:{seconds % 60:02d}"

    def _phase_elapsed(self, snap: LiveSnapshot) -> str:
        seconds = max(0, int(time.time() - snap.phase_started_at))
        return f"{seconds // 60:02d}:{seconds % 60:02d}"

    def _bar(self, snap: LiveSnapshot, width: int = 28) -> str:
        total = max(1, snap.phase_total)
        progress = max(0, min(snap.phase_progress, total))
        filled = int(width * progress / total)
        return "█" * filled + "░" * (width - filled)

    def _term_width(self) -> int:
        try:
            return max(96, min(120, shutil.get_terminal_size((100, 40)).columns))
        except Exception:
            return 100

    def _severity_color(self, severity: str) -> str:
        severity = str(severity or "INFO").upper()
        if severity == "CRITICAL":
            return BOLD + RED
        if severity == "HIGH":
            return RED
        if severity == "MEDIUM":
            return YELLOW
        if severity == "LOW":
            return BLUE
        return GREEN

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            severity = str(finding.get("severity") or "INFO").upper()
            counts[severity if severity in counts else "INFO"] += 1
        return counts

    def _report_lines(self) -> list[str]:
        if not self.report_paths:
            return ["CLI report paths will be written after finalization."]
        preferred = ["final_findings_dashboard_md", "final_findings_dashboard_json", "autonomous_report_md", "parameter_inventory_v2", "evidence_index_md", "agent_trace_md", "tool_router_matrix_json", "cli_final_dashboard_md"]
        lines: list[str] = []
        for key in preferred:
            if key in self.report_paths:
                lines.append(f"{key}: {self.report_paths[key]}")
        for key, value in self.report_paths.items():
            if key not in preferred:
                lines.append(f"{key}: {value}")
        return lines

    def _tool_rows(self, snap: LiveSnapshot) -> list[str]:
        rows = [
            f"Total: {snap.tools_total:<3} Running: {snap.tools_running:<2} Completed: {snap.tools_completed:<3} Failed: {snap.tools_failed:<2} Blocked: {snap.tools_blocked:<2} Skip: {snap.tools_skipped:<2}",
            f"Inactive: {snap.tools_inactive:<3} Needs Config: {snap.tools_not_ready:<3}   (Skip means actually selected but missing runtime input)",
            "─" * 76,
        ]
        for tool in self.TOOL_ORDER:
            if tool == snap.current_tool or (tool == "safe_canary_reflection" and snap.current_tool in {"test_parameter", "reflection_canary", "redirect_review"}):
                mark = f"{SPINNER[snap.spinner_index]} running"
            elif tool in {"report_generator", "llm_public_reasoning"} and snap.phase_progress < 85:
                mark = "◻ queued"
            elif snap.tools_completed > 0 and tool not in {snap.current_tool}:
                mark = "✓ completed" if tool in {"crawler_v2", "browser_crawler"} and snap.phase_progress > 40 else "◻ queued"
            else:
                mark = "◻ queued"
            rows.append(f"► {tool:<30} {mark}")
        return rows[:17]

    def _trace_rows(self, snap: LiveSnapshot, traces: list[str]) -> list[str]:
        rows = ["Turn  Agent                   Action                     Status     Handoff"]
        rows.append(f"{snap.turn:<5} {_clean(snap.current_agent, 22):<22} {_clean(snap.action, 26):<26} running    {_clean(snap.phase, 12)}")
        for trace in traces[-3:][::-1]:
            rows.append(f"{max(0, snap.turn - 1):<5} {'TraceLogger':<22} {_clean(trace, 26):<26} completed  Analyzer")
        return rows

    def render_text(self, *, final: bool = False, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            events = list(self.events)
            traces = list(self.traces)
        c = lambda text, col: _colorize(text, col, color)
        width = 95
        spinner = SPINNER[snap.spinner_index]
        header_line = f" VulnScope v{VERSION}   Target: {_clean(snap.domain, 24)}   Mode: {snap.mode}   Time: {self._elapsed()}   Phase: {self._phase_elapsed(snap)} "
        header = [
            c("┌" + "─" * (width - 2) + "┐", CYAN),
            c("│" + _pad(header_line, width - 2) + "│", CYAN),
            c("└" + "─" * (width - 2) + "┘", CYAN),
            "",
        ]
        reasoning = [f"🧠 THINKING: {_clean(snap.decision if snap.decision != '—' else snap.action, 82)}", f"   {_clean(snap.hypothesis, 82)}"]
        context = [
            f"📡 Endpoint: {_clean(snap.endpoint, 78)}",
            f"🗂️  Path: {_clean(snap.path, 82)}",
            f"📝 Parameter: {_clean(snap.parameters, 78)}",
            f"🧪 Payload: {_clean(snap.probe_string, 80)}",
            f"💡 Hypothesis: {_clean(snap.hypothesis, 76)}",
            f"🔍 Evidence: {_clean(snap.evidence, 78)}",
            f"📊 Phase: {spinner} {snap.phase}  [{c(self._bar(snap), GREEN)}] {snap.phase_progress}/{max(1, snap.phase_total)}",
            f"📈 Surface: urls={snap.urls_found} paths={snap.paths_found} params={snap.params_found} forms={snap.forms_found} js={snap.js_found} api={snap.api_routes_found} req={snap.requests}",
        ]
        logs = events[-10:] or ["Waiting for first scan event…"]
        footer = ["─" * width, "  Press Ctrl+C to stop scan  |  All findings auto-reported  |  Zero-impact mode", "─" * width]
        lines: list[str] = []
        lines.extend(header)
        lines.extend(_box("Agent Trace", self._trace_rows(snap, traces), color=CYAN, enabled=color, width=width))
        lines.append("")
        lines.extend(_box("Tool Matrix", self._tool_rows(snap), color=MAGENTA, enabled=color, width=width))
        lines.append("")
        lines.extend(_box("Live Reasoning", reasoning, color=YELLOW, enabled=color, width=width))
        lines.append("")
        lines.extend(_box("Current Context", context, color=BLUE, enabled=color, width=width))
        lines.append("")
        lines.extend(_box("Live Log (10 most recent)", logs, color=GREEN, enabled=color, width=width))
        lines.extend(footer)
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def final_text(self, *, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            findings = [dict(item) for item in self.finding_details]
        c = lambda text, col: _colorize(text, col, color)
        confirmed = [item for item in findings if item.get("confirmation") == "confirmed"]
        counts = self._severity_counts(findings)
        total_label = f"{len(confirmed)} confirmed vulnerabilities" if confirmed else f"{len(findings)} findings / review leads"
        lines = [
            "=" * 96,
            c("FINAL ASSESSMENT DASHBOARD", CYAN),
            "=" * 96,
            f"Target:          {snap.domain}",
            f"Scan Mode:       {snap.mode}",
            f"Total Time:      {self._elapsed()}",
            f"Last Phase:      {snap.phase}",
            f"Total Requests:  {snap.requests}",
            f"Surface:         urls={snap.urls_found} paths={snap.paths_found} params={snap.params_found} forms={snap.forms_found} js={snap.js_found} api={snap.api_routes_found}",
            f"Tool Status:     completed={snap.tools_completed} failed={snap.tools_failed} skip={snap.tools_skipped} inactive={snap.tools_inactive} needs_config={snap.tools_not_ready}",
            f"Total Findings:  {total_label}",
            f"Severity Counts: CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']} INFO:{counts['INFO']}",
            "",
            "────────────────────────────────────────────────────────────────────────────────",
            "CONFIRMED VULNERABILITIES / REVIEW LEADS — DETAILED BREAKDOWN",
            "────────────────────────────────────────────────────────────────────────────────",
            "",
        ]
        if not findings:
            lines.extend([c("No vulnerabilities were confirmed under the selected safe scope and request budget.", YELLOW), "Review dynamic-tool-phase-summary.json, phase-runner-summary.json, parameter-inventory-v2.json, deep-scan-prioritization.json, and evidence-index.md for exact coverage.", ""])
        for idx, finding in enumerate(findings, 1):
            severity = str(finding.get("severity", "INFO")).upper()
            title = finding.get("type", "Security Finding")
            status = str(finding.get("confirmation", "review_lead")).replace("_", " ").upper()
            lines.extend([c(f"═══ FINDING #{idx} ═══", self._severity_color(severity)), f"WHAT:       {title} ({severity}) — {status}", f"WHY:        {finding.get('description')}", f"WHERE:      {finding.get('url')}", f"Parameter:  {finding.get('parameter')}", f"Probe:      {finding.get('test_string')}", f"EVIDENCE:   {finding.get('evidence')}", f"CVSS:       {finding.get('cvss')}", f"CONFIDENCE: {finding.get('confidence')}", "REPRODUCTION:"])
            for line in str(finding.get("reproduction") or "Review evidence inside authorized scope.").splitlines():
                lines.append(f"  {line}")
            lines.extend(["", "────────────────────────────────────────────────────────────────────────────────", ""])
        lines.extend(["=" * 96, "✅ Full report written to: " + str(Path("reports/output/cai-superior") / snap.domain), "", "--- Report Files ---"])
        for entry in self._report_lines():
            lines.append(f"- {entry}")
        lines.append("=" * 96)
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def show_final(self) -> None:
        if self.enabled:
            print(self.final_text(color=self.interactive), flush=True)

    def draw(self, *, final: bool = False) -> None:
        if not self.enabled:
            return
        text = self.final_text(color=self.interactive) if final else self.render_text(final=False, color=self.interactive)
        if self.interactive:
            raw_lines = _strip_ansi(text).splitlines()
            height = max(self._last_height, len(raw_lines))
            padded_lines: list[str] = []
            term_width = self._term_width()
            split = text.splitlines()
            for idx in range(height):
                line = split[idx] if idx < len(split) else ""
                clear = " " * max(0, term_width - len(_strip_ansi(line)))
                padded_lines.append(line + clear)
            self._last_height = len(raw_lines)
            sys.stdout.write("\033[H" + "\n".join(padded_lines))
            sys.stdout.flush()
        else:
            now = time.time()
            if final or now - self._last_render_at > 5:
                print(_strip_ansi(text), flush=True)
                self._last_render_at = now

    def write_reports(self, out: Path) -> dict[str, str]:
        out.mkdir(parents=True, exist_ok=True)
        with self.lock:
            payload = {"snapshot": asdict(self.snapshot), "events": list(self.events), "traces": list(self.traces), "findings": [dict(item) for item in self.finding_details], "generated_at": time.time(), "interface": "kali_cli", "dashboard": "classic_phase_stable_cli", "version": VERSION, "website_dashboard": False}
        session_json_path = out / "cli-session.json"
        final_json_path = out / "cli-final-dashboard.json"
        final_md_path = out / "cli-final-dashboard.md"
        findings_json_path = out / "detailed-findings.json"
        session_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        final_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        findings_json_path.write_text(json.dumps(payload["findings"], indent=2, ensure_ascii=False), encoding="utf-8")
        reports = {"cli_session_json": str(session_json_path), "cli_final_dashboard_json": str(final_json_path), "cli_final_dashboard_md": str(final_md_path), "detailed_findings_json": str(findings_json_path)}
        self.report_paths = dict(reports)
        final_md_path.write_text("# VulnScope Classic Phase-Stable Final Dashboard\n\n```text\n" + self.final_text(color=False) + "\n```\n", encoding="utf-8")
        return reports
