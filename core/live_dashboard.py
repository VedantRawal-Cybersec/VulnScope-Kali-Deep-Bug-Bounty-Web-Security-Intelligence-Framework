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
WHITE = "\033[37m"
DIM = "\033[2m"

SENSITIVE_PATTERNS = [re.compile(r"(?i)(api[_-]?key|token|secret|authorization|cookie)=([^\s&;]+)")]


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
    action: str = "Initializing safe autonomous loop"
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
    safety_status: str = "Scope locked • safe methods only • zero-impact"
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
    request_line = f"GET {path}" + (("?" + parsed.query) if parsed.query else "")
    return {"target": normalized, "domain": domain, "endpoint": normalized, "request_line": request_line, "path": path, "parameters": query, "method": "GET"}


class LiveDashboard:
    """Stable in-place Kali CLI dashboard for transparent defensive execution."""

    def __init__(self, target: str, *, max_turns: int = 0, enabled: bool = True, live_stream: bool = False, refresh_interval: float = 0.5, interactive: bool | None = None) -> None:
        parts = target_components(target)
        self.snapshot = LiveSnapshot(target=_clean(parts["target"], 180), max_turns=max_turns, domain=_clean(parts["domain"], 100), endpoint=_clean(parts["endpoint"], 180), request_line=_clean(parts["request_line"], 180), path=_clean(parts["path"], 140), parameters=_clean(parts["parameters"], 180), method=parts.get("method", "GET"))
        self.enabled = bool(enabled) and os.getenv("VULNSCOPE_NO_CLI_DASHBOARD", "0") != "1"
        self.live_stream = bool(live_stream) and os.getenv("VULNSCOPE_NO_LIVE_DASHBOARD", "0") != "1"
        self.interactive = sys.stdout.isatty() if interactive is None else bool(interactive)
        self.refresh_interval = max(float(refresh_interval), 0.2)
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.traces: list[str] = []
        self.finding_details: list[dict[str, Any]] = []
        self.max_events = 30
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
            print("[vulnscope] live stream active; stable TTY dashboard unavailable in this output mode", flush=True)

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
                        setattr(self.snapshot, key, _clean(value, 220))

    def event(self, level: str, message: str) -> None:
        level = str(level or "INFO").upper()
        icon = {"SUCCESS": "OK", "INFO": "INFO", "WARNING": "WARN", "BLOCKED": "BLOCK", "FINDING": "FIND", "THINKING": "AI", "HANDOFF": "HAND"}.get(level, "LOG")
        rendered = f"{time.strftime('%H:%M:%S')} {icon:<5} {_clean(message, 220)}"
        with self.lock:
            self.events.append(rendered)
            self.events = self.events[-self.max_events :]
            self.snapshot.latest_status = level.lower()
        if self.enabled and self.live_stream and not self.interactive and level in {"WARNING", "BLOCKED", "FINDING", "SUCCESS"}:
            print(_strip_ansi(rendered), flush=True)

    def trace(self, message: str) -> None:
        with self.lock:
            self.traces.append(f"{time.strftime('%H:%M:%S')} {_clean(message, 240)}")
            self.traces = self.traces[-12:]

    def add_finding(self, finding_type: str, description: str, severity: str = "INFO", *, url: str = "", parameter: str = "", test_string: str = "", evidence: str = "", cvss: str = "N/A", confidence: str = "N/A", reproduction: str = "", confirmation: str = "review_lead") -> dict[str, Any]:
        severity = _clean(severity or "INFO", 30).upper()
        confirmation = _clean(confirmation or "review_lead", 40).lower()
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            finding = {"type": _clean(finding_type or "Security Review Lead", 120), "severity": severity, "description": _clean(description or "Evidence requires analyst review.", 400), "url": _clean(url or snap.endpoint, 240), "domain": _clean(snap.domain, 120), "request_line": _clean(snap.request_line, 220), "path": _clean(snap.path, 180), "parameter": _clean(parameter or snap.parameters, 220), "test_string": _clean(test_string or snap.probe_string, 220), "evidence": _clean(evidence or snap.evidence, 800), "cvss": _clean(cvss, 80), "confidence": _clean(confidence, 80), "reproduction": _clean_multiline(reproduction or "Review generated evidence and validate only inside the authorized scope."), "confirmation": confirmation, "recorded_at": time.time()}
            self.finding_details.append(finding)
            self.snapshot.findings = len(self.finding_details)
            self.snapshot.latest_finding = f"{severity} {finding['type']}"
            if confirmation == "confirmed":
                self.snapshot.confirmed += 1
            elif confirmation in {"potential", "review_lead"}:
                self.snapshot.potential += 1
            else:
                self.snapshot.informational += 1
            self.events.append(f"{time.strftime('%H:%M:%S')} FIND  {severity} {finding['type']}: {finding['description']}")
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

    def _bar(self, width: int = 30) -> str:
        total = max(1, self.snapshot.phase_total)
        progress = max(0, min(self.snapshot.phase_progress, total))
        filled = int(width * progress / total)
        return "█" * filled + "░" * (width - filled)

    def _term_width(self) -> int:
        try:
            return max(96, min(140, shutil.get_terminal_size((116, 40)).columns))
        except Exception:
            return 116

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
        preferred = ["scan_quality_md", "autonomous_report_md", "parameter_inventory_v2", "evidence_index_md", "cli_final_dashboard_md", "detailed_findings_json", "react_run_md"]
        lines = []
        for key in preferred:
            if key in self.report_paths:
                lines.append(f"{key}: {self.report_paths[key]}")
        for key, value in self.report_paths.items():
            if key not in preferred:
                lines.append(f"{key}: {value}")
        return lines

    def _panel_line(self, label: str, value: Any, width: int = 54) -> str:
        return f"{label:<18} {_clean(value, width)}"

    def render_text(self, *, final: bool = False, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            events = list(self.events)
            traces = list(self.traces)
        c = (lambda value: value) if color else (lambda value: "")
        width = self._term_width()
        sep = "─" * min(width, 132)
        progress = f"[{self._bar()}] {snap.phase_progress}/{max(1, snap.phase_total)}"
        lines = [f"{c(CYAN)}VULNSCOPE ULTIMATE AUTONOMOUS SECURITY AI{c(RESET)}  {c(DIM)}single stable live dashboard{c(RESET)}", sep, f"Scan ID: {snap.scan_id} | Target: {snap.target} | Mode: {snap.mode} | Auth: {snap.authorization_status} | Time: {self._elapsed()}", f"Ollama: {snap.ollama_status} | Phase: {snap.phase} | Progress: {progress}", sep, f"{c(YELLOW)}Current Activity{c(RESET)}", f"Domain: {snap.domain}", f"Endpoint: {snap.endpoint}", f"Full Request: {snap.request_line}", f"Path: {snap.path}", f"Parameters: {snap.parameters}", f"Safe string under test: {snap.probe_string}", f"Evidence snippet: {snap.evidence}", self._panel_line("Agent", snap.current_agent) + " | " + self._panel_line("Tool", snap.current_tool), self._panel_line("Action", snap.action, 88), self._panel_line("Response", f"{snap.response_code} / {snap.response_time_ms}ms"), sep, f"{c(YELLOW)}Discovered Surface{c(RESET)}  URLs:{snap.urls_found}  Paths:{snap.paths_found}  Params:{snap.params_found}  Forms:{snap.forms_found}  JS:{snap.js_found}  API-like:{snap.api_routes_found}", f"{c(YELLOW)}Agent Trace{c(RESET)}  Turn:{snap.turn}/{snap.max_turns or '∞'}  Decision:{snap.decision}  Handoff:{snap.handoff}", f"{c(YELLOW)}Tool Matrix{c(RESET)}  Total:{snap.tools_total}  Running:{snap.tools_running}  Completed:{snap.tools_completed}  Failed:{snap.tools_failed}  Skipped:{snap.tools_skipped}  Blocked:{snap.tools_blocked}", f"{c(YELLOW)}Findings{c(RESET)}  Confirmed:{snap.confirmed}  Potential:{snap.potential}  Info:{snap.informational}  Total:{snap.findings}  Latest:{snap.latest_finding}", f"{c(GREEN)}Safety{c(RESET)}  {snap.safety_status}", sep, f"{c(YELLOW)}Recent Handoffs / Decisions{c(RESET)}"]
        lines.extend(traces[-8:] if traces else ["No handoff has started yet."])
        lines += [sep, f"{c(YELLOW)}Live Logs (last {self.max_events}){c(RESET)}"]
        lines.extend(events[-self.max_events :] if events else ["Waiting for first scan event…"])
        lines.append(sep)
        lines.append("Ctrl+C: stop safely • Reports are written on completion/interruption" if not final else "Final CLI dashboard")
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def final_text(self, *, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            findings = [dict(item) for item in self.finding_details]
            events = list(self.events)
        c = (lambda value: value) if color else (lambda value: "")
        confirmed = [item for item in findings if item.get("confirmation") == "confirmed"]
        counts = self._severity_counts(findings)
        severity_line = f"CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']} INFO:{counts['INFO']}"
        lines = ["=" * 90, f"{c(CYAN)}VULNSCOPE ULTIMATE FINAL KALI CLI DASHBOARD{c(RESET)}", f"Target: {snap.target}", f"Scan ID: {snap.scan_id}", f"Mode: {snap.mode}", f"Ollama: {snap.ollama_status}", f"Endpoint: {snap.endpoint}", f"Full Request: {snap.request_line}", f"Path: {snap.path}", f"Parameters: {snap.parameters}", f"Evidence snippet: {snap.evidence}", f"Time: {self._elapsed()} | Requests: {snap.requests} | Findings/leads: {len(findings)} | Confirmed: {len(confirmed)}", f"Severity Summary: {severity_line}", f"Confirmed Findings: {len(confirmed)}", "─" * 90]
        if not findings:
            lines.append(f"{c(YELLOW)}No vulnerabilities were confirmed. Review surface inventory and evidence reports for coverage details.{c(RESET)}")
        else:
            for idx, finding in enumerate(findings, 1):
                severity = str(finding.get("severity", "INFO")).upper()
                status = str(finding.get("confirmation", "review_lead")).replace("_", " ").upper()
                lines += ["", f"{c(self._severity_color(severity))}FINDING #{idx} — {severity} — {status}{c(RESET)}", f"WHAT: {finding.get('type')}", f"WHY: {finding.get('description')}", f"WHERE: {finding.get('url')}", f"REQUEST: {finding.get('request_line')}", f"PATH: {finding.get('path')}", f"PARAMETER: {finding.get('parameter')}", f"SAFE PROBE: {finding.get('test_string')}", f"TESTED EVIDENCE: {finding.get('test_string')}", f"EVIDENCE: {finding.get('evidence')}", f"CONFIDENCE: {finding.get('confidence')}", "REPRODUCTION / VALIDATION STEPS:"]
                for line in str(finding.get("reproduction") or "See evidence above.").splitlines():
                    lines.append(f"  {line}")
                lines.append("─" * 90)
        lines.append("\n--- Final Activity Log ---")
        for entry in events[-self.max_events :]:
            lines.append(entry)
        lines.append("\n--- Report Files ---")
        for entry in self._report_lines():
            lines.append(f"- {entry}")
        lines.append("=" * 90)
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
            padded_lines = []
            term_width = self._term_width()
            split_lines = text.splitlines()
            for idx in range(height):
                line = split_lines[idx] if idx < len(split_lines) else ""
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
            payload = {"snapshot": asdict(self.snapshot), "events": list(self.events), "traces": list(self.traces), "findings": [dict(item) for item in self.finding_details], "generated_at": time.time(), "interface": "kali_cli", "dashboard": "stable_live_cli", "website_dashboard": False}
        session_json_path = out / "cli-session.json"
        final_json_path = out / "cli-final-dashboard.json"
        final_md_path = out / "cli-final-dashboard.md"
        findings_json_path = out / "detailed-findings.json"
        session_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        final_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        findings_json_path.write_text(json.dumps(payload["findings"], indent=2, ensure_ascii=False), encoding="utf-8")
        reports = {"cli_session_json": str(session_json_path), "cli_final_dashboard_json": str(final_json_path), "cli_final_dashboard_md": str(final_md_path), "detailed_findings_json": str(findings_json_path)}
        self.report_paths = dict(reports)
        final_md_path.write_text("# VulnScope Stable Kali CLI Final Dashboard\n\n```text\n" + self.final_text(color=False) + "\n```\n", encoding="utf-8")
        return reports
