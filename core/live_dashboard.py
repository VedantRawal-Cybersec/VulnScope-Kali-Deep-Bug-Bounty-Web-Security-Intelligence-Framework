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
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
WHITE = "\033[37m"

VERSION = "1.12.0"

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|authorization|cookie|session|password)=([^\s&;]+)"),
]


@dataclass
class LiveSnapshot:
    target: str
    scan_id: str = field(default_factory=lambda: "scan_" + uuid.uuid4().hex[:10])
    mode: str = "passive"
    authorization_status: str = "confirmed"
    ollama_status: str = "checking"
    phase: str = "Starting"
    phase_progress: int = 0
    phase_total: int = 100
    turn: int = 0
    max_turns: int = 0
    findings: int = 0
    requests: int = 0
    action: str = "Initializing autonomous ReAct loop"
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
    safety_status: str = "Scope locked • passive + safe-active only • zero-impact"
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
    confirmed: int = 0
    potential: int = 0
    informational: int = 0
    latest_finding: str = "—"
    started_at: float = field(default_factory=time.time)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def _clean(value: Any, limit: int = 120) -> str:
    text = str(value if value is not None else "—")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip() or "—"
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def _clean_multiline(value: Any, limit: int = 1200) -> str:
    text = str(value if value is not None else "—").replace("\r", "")
    lines = [_clean(line, 220) for line in text.splitlines()]
    text = "\n".join(lines).strip() or "—"
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def target_components(target: str) -> dict[str, str]:
    raw = str(target or "").strip()
    normalized = raw if "://" in raw else "https://" + raw
    parsed = urlparse(normalized)
    domain = (parsed.hostname or parsed.netloc or raw).split(":")[0].lower().strip() or "—"
    path = parsed.path or "/"
    query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
    endpoint = normalized
    request_line = f"GET {path}"
    if parsed.query:
        request_line += "?" + parsed.query
    return {"target": normalized, "domain": domain, "endpoint": endpoint, "request_line": request_line, "path": path, "parameters": query, "method": "GET"}


def _colorize(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _pad(text: str, width: int) -> str:
    raw = _strip_ansi(text)
    if len(raw) > width:
        raw = raw[: max(0, width - 1)] + "…"
        text = raw
    return text + (" " * max(0, width - len(raw)))


def _box(title: str, lines: list[str], *, color: str = CYAN, enabled: bool = True, width: int = 95) -> list[str]:
    inner = width - 2
    out = [
        _colorize("┌─ " + title + " " + "─" * max(0, inner - len(title) - 3) + "┐", color, enabled)
    ]
    for line in lines:
        out.append(_colorize("│", color, enabled) + " " + _pad(line, inner - 2) + " " + _colorize("│", color, enabled))
    out.append(_colorize("└" + "─" * inner + "┘", color, enabled))
    return out


class LiveDashboard:
    """CAI-style live dashboard with colored panels and final assessment output."""

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
        "report_generator",
        "llm_public_reasoning",
        "llm_evidence_validator",
    ]

    def __init__(
        self,
        target: str,
        *,
        max_turns: int = 0,
        enabled: bool = True,
        live_stream: bool = False,
        refresh_interval: float = 0.5,
        interactive: bool | None = None,
    ) -> None:
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

    def start(self) -> None:
        if not self.enabled or not self.live_stream:
            return
        self.running = True
        if self.interactive:
            sys.stdout.write("\033[?1049h\033[?25l\033[H\033[J")
            sys.stdout.flush()
            self._alt_screen = True
            self.thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self.thread.start()
        else:
            print("[vulnscope] live dashboard active; stable in-place TTY dashboard unavailable in this output mode", flush=True)

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
        with self.lock:
            endpoint_value = kwargs.get("endpoint") or kwargs.get("target_url") or kwargs.get("url")
            if endpoint_value and not any(k in kwargs for k in ("domain", "request_line", "path", "parameters")):
                parts = target_components(str(endpoint_value))
                kwargs.setdefault("domain", parts["domain"])
                kwargs.setdefault("endpoint", parts["endpoint"])
                kwargs.setdefault("request_line", parts["request_line"])
                kwargs.setdefault("path", parts["path"])
                kwargs.setdefault("parameters", parts["parameters"])
            for key, value in kwargs.items():
                if hasattr(self.snapshot, key):
                    if key in {"phase_progress", "phase_total", "turn", "max_turns", "findings", "requests", "urls_found", "paths_found", "params_found", "forms_found", "js_found", "api_routes_found", "tools_total", "tools_running", "tools_completed", "tools_failed", "tools_skipped", "tools_blocked", "confirmed", "potential", "informational"}:
                        try:
                            setattr(self.snapshot, key, int(value))
                        except Exception:
                            setattr(self.snapshot, key, 0)
                    else:
                        setattr(self.snapshot, key, _clean(value, 260))

    def event(self, level: str, message: str) -> None:
        level = str(level or "INFO").upper()
        icon = {
            "SUCCESS": "✅",
            "INFO": "ℹ️ ",
            "WARNING": "⚠️ ",
            "BLOCKED": "🛡️ ",
            "FINDING": "🔥",
            "THINKING": "🧠",
            "HANDOFF": "🔁",
            "ERROR": "❌",
        }.get(level, "• ")
        rendered = f"[{time.strftime('%H:%M:%S')}] {icon} {_clean(message, 240)}"
        with self.lock:
            self.events.append(rendered)
            self.events = self.events[-self.max_events :]
            self.snapshot.latest_status = level.lower()
        if self.enabled and self.live_stream and not self.interactive:
            if level in {"WARNING", "BLOCKED", "FINDING", "SUCCESS", "ERROR"}:
                print(_strip_ansi(rendered), flush=True)

    def trace(self, message: str) -> None:
        with self.lock:
            self.traces.append(f"{time.strftime('%H:%M:%S')} {_clean(message, 240)}")
            self.traces = self.traces[-8:]

    def add_finding(
        self,
        finding_type: str,
        description: str,
        severity: str = "INFO",
        *,
        url: str = "",
        parameter: str = "",
        test_string: str = "",
        evidence: str = "",
        cvss: str = "N/A",
        confidence: str = "N/A",
        reproduction: str = "",
        confirmation: str = "review_lead",
    ) -> dict[str, Any]:
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
            self.events = self.events[-self.max_events :]
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

    def _bar(self, width: int = 32) -> str:
        total = max(1, self.snapshot.phase_total)
        progress = max(0, min(self.snapshot.phase_progress, total))
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
        preferred = [
            "final_findings_dashboard_md",
            "final_findings_dashboard_json",
            "autonomous_report_md",
            "parameter_inventory_v2",
            "evidence_index_md",
            "agent_trace_md",
            "tool_router_matrix_json",
            "cli_final_dashboard_md",
        ]
        lines = []
        for key in preferred:
            if key in self.report_paths:
                lines.append(f"{key}: {self.report_paths[key]}")
        for key, value in self.report_paths.items():
            if key not in preferred:
                lines.append(f"{key}: {value}")
        return lines

    def _tool_rows(self, snap: LiveSnapshot) -> list[str]:
        running = max(0, int(snap.tools_running))
        completed = max(0, int(snap.tools_completed))
        failed = max(0, int(snap.tools_failed))
        skipped = max(0, int(snap.tools_skipped))
        blocked = max(0, int(snap.tools_blocked))
        rows: list[str] = [
            f"Total: {snap.tools_total:<3} Running: {running:<2} Completed: {completed:<3} Failed: {failed:<2} Blocked: {blocked:<2} Skip: {skipped:<2}",
            "─" * 76,
        ]
        for tool in self.TOOL_ORDER:
            if tool == snap.current_tool or (tool == "safe_canary_reflection" and snap.current_tool in {"test_parameter", "reflection_canary"}):
                mark = "⏳ running "
            elif tool in {"report_generator", "llm_evidence_validator"} and snap.phase_progress < 85:
                mark = "◻ queued  "
            elif completed > 0:
                mark = "✔ completed"
                completed -= 1
            else:
                mark = "◻ queued  "
            rows.append(f"► {tool:<26} {mark}")
        return rows[:14]

    def _trace_rows(self, snap: LiveSnapshot, traces: list[str]) -> list[str]:
        rows = ["Turn  Agent                   Action                     Status     Handoff"]
        rows.append(f"{snap.turn:<5} {_clean(snap.current_agent, 22):<22} {_clean(snap.action, 26):<26} running    {_clean(snap.handoff, 10)}")
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
        header = [
            c("╔" + "═" * (width - 2) + "╗", CYAN),
            c(f"║  VulnScope v{VERSION:<8} Target: {_clean(snap.domain, 20):<20} Mode: {snap.mode:<11} Time: {self._elapsed():<5} ║", CYAN),
            c("╚" + "═" * (width - 2) + "╝", CYAN),
            "",
        ]
        reasoning = [
            f"🧠 THINKING: {_clean(snap.decision if snap.decision != '—' else snap.action, 82)}",
            f"   {_clean(snap.hypothesis, 82)}",
        ]
        context = [
            f"📡 Endpoint: {_clean(snap.endpoint, 78)}",
            f"🗂️  Path: {_clean(snap.path, 82)}",
            f"📝 Parameter: {_clean(snap.parameters, 78)}",
            f"💉 Payload: {_clean(snap.probe_string, 80)}",
            f"💡 Hypothesis: {_clean(snap.hypothesis, 76)}",
            f"🔍 Evidence: {_clean(snap.evidence, 78)}",
            f"📊 Phase: {snap.phase}  [{c(self._bar(), GREEN)}] {snap.phase_progress}/{max(1, snap.phase_total)}",
        ]
        logs = events[-10:] or ["Waiting for first scan event…"]
        footer = [
            "─" * width,
            "  Press Ctrl+C to stop scan  |  All findings auto-reported  |  Zero-impact mode",
            "─" * width,
        ]
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
            c("╔" + "═" * 79 + "╗", CYAN),
            c("║                     FINAL ASSESSMENT DASHBOARD                               ║", CYAN),
            c("╚" + "═" * 79 + "╝", CYAN),
            "",
            f"Target:          {snap.domain}",
            f"Scan Mode:       {snap.mode}",
            f"Total Time:      {self._elapsed()}",
            f"Total Requests:  {snap.requests}",
            f"Total Findings:  {total_label}",
            f"Severity Counts: CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']} INFO:{counts['INFO']}",
            "",
            "────────────────────────────────────────────────────────────────────────────────",
            "CONFIRMED VULNERABILITIES / REVIEW LEADS — DETAILED BREAKDOWN",
            "────────────────────────────────────────────────────────────────────────────────",
            "",
        ]
        if not findings:
            lines.extend([
                c("No vulnerabilities were confirmed under the selected safe scope and request budget.", YELLOW),
                "Review final-findings-dashboard.md, parameter-inventory-v2.json, and evidence-index.md for coverage.",
                "",
            ])
        for idx, finding in enumerate(findings, 1):
            severity = str(finding.get("severity", "INFO")).upper()
            title = finding.get("type", "Security Finding")
            status = str(finding.get("confirmation", "review_lead")).replace("_", " ").upper()
            lines.extend([
                c(f"═══ FINDING #{idx} ═══", self._severity_color(severity)),
                f"WHAT:       {title} ({severity}) — {status}",
                f"WHY:        {finding.get('description')}",
                f"WHERE:      {finding.get('url')}",
                f"Parameter:  {finding.get('parameter')}",
                f"Payload:    {finding.get('test_string')}",
                f"EVIDENCE:   {finding.get('evidence')}",
                f"CVSS:       {finding.get('cvss')}",
                f"CONFIDENCE: {finding.get('confidence')}",
                "REPRODUCTION:",
            ])
            for line in str(finding.get("reproduction") or "Review evidence inside authorized scope.").splitlines():
                lines.append(f"  {line}")
            lines.extend(["", "────────────────────────────────────────────────────────────────────────────────", ""])
        lines.extend([
            "=" * 96,
            "✅ Full report written to: " + str(Path("reports/output/cai-superior") / snap.domain),
            "   • final-findings-dashboard.md",
            "   • autonomous-scan-report.md",
            "   • autonomous-scan-report.json",
            "   • evidence/evidence-index.md",
            "   • agent-trace.md",
            "   • tool-router-matrix.json",
            "📊 Dashboard displayed above.",
            "",
            "--- Report Files ---",
        ])
        for entry in self._report_lines():
            lines.append(f"- {entry}")
        lines.append("=" * 96)
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def show_final(self) -> None:
        if not self.enabled:
            return
        print(self.final_text(color=self.interactive), flush=True)

    def draw(self, *, final: bool = False) -> None:
        if not self.enabled:
            return
        text = self.final_text(color=self.interactive) if final else self.render_text(final=False, color=self.interactive)
        if self.interactive:
            raw_lines = _strip_ansi(text).splitlines()
            height = max(self._last_height, len(raw_lines))
            padded_lines = []
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
            print(_strip_ansi(text), flush=True)

    def write_reports(self, out: Path) -> dict[str, str]:
        out.mkdir(parents=True, exist_ok=True)
        with self.lock:
            payload = {
                "snapshot": asdict(self.snapshot),
                "events": list(self.events),
                "traces": list(self.traces),
                "findings": [dict(item) for item in self.finding_details],
                "generated_at": time.time(),
                "interface": "kali_cli",
                "dashboard": "cai_style_live_cli",
                "version": VERSION,
                "website_dashboard": False,
            }
        session_json_path = out / "cli-session.json"
        final_json_path = out / "cli-final-dashboard.json"
        final_md_path = out / "cli-final-dashboard.md"
        findings_json_path = out / "detailed-findings.json"
        session_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        final_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        findings_json_path.write_text(json.dumps(payload["findings"], indent=2, ensure_ascii=False), encoding="utf-8")
        reports = {
            "cli_session_json": str(session_json_path),
            "cli_final_dashboard_json": str(final_json_path),
            "cli_final_dashboard_md": str(final_md_path),
            "detailed_findings_json": str(findings_json_path),
        }
        self.report_paths = dict(reports)
        final_md_path.write_text("# VulnScope CAI-Style Final Dashboard\n\n```text\n" + self.final_text(color=False) + "\n```\n", encoding="utf-8")
        return reports
