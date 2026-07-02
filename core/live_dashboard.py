#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import threading
import time
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

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret)=([^\s&]+)"),
]


@dataclass
class LiveSnapshot:
    target: str
    phase: str = "Starting"
    phase_progress: int = 0
    phase_total: int = 100
    turn: int = 0
    max_turns: int = 0
    findings: int = 0
    requests: int = 0
    action: str = "Initializing safe autonomous loop"
    domain: str = "—"
    endpoint: str = "—"
    request_line: str = "GET /"
    path: str = "—"
    parameters: str = "—"
    probe_string: str = "—"
    hypothesis: str = "—"
    evidence: str = "—"
    safety_status: str = "Scope locked • safe methods only • zero-impact"
    latest_status: str = "waiting"
    started_at: float = field(default_factory=time.time)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


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
    query = parsed.query or "—"
    endpoint = normalized
    request_line = f"GET {path}"
    if parsed.query:
        request_line += "?" + parsed.query
    return {
        "target": normalized,
        "domain": domain,
        "endpoint": endpoint,
        "request_line": request_line,
        "path": path,
        "parameters": query,
    }


class LiveDashboard:
    """Kali CLI dashboard for transparent, zero-impact autonomous execution."""

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
            parameters=_clean(parts["parameters"], 160),
        )
        self.enabled = bool(enabled) and os.getenv("VULNSCOPE_NO_CLI_DASHBOARD", "0") != "1"
        self.live_stream = bool(live_stream) and os.getenv("VULNSCOPE_NO_LIVE_DASHBOARD", "0") != "1"
        self.interactive = sys.stdout.isatty() if interactive is None else bool(interactive)
        self.refresh_interval = max(float(refresh_interval), 0.2)
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.finding_details: list[dict[str, Any]] = []
        self.max_events = 10
        self.running = False
        self.thread: threading.Thread | None = None
        self.report_paths: dict[str, str] = {}

    def start(self) -> None:
        if not self.enabled or not self.live_stream:
            return
        self.running = True
        if self.interactive:
            self.thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self.thread.start()
        else:
            print("[vulnscope-ultimate-cli] live terminal view started", flush=True)

    def _refresh_loop(self) -> None:
        while self.running:
            self.draw(final=False)
            time.sleep(self.refresh_interval)

    def stop(self, *, final: bool = False) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        if final and self.enabled:
            self.show_final()

    def update(self, **kwargs: Any) -> None:
        with self.lock:
            for key, value in kwargs.items():
                if hasattr(self.snapshot, key):
                    if key in {"phase_progress", "phase_total", "turn", "max_turns", "findings", "requests"}:
                        try:
                            setattr(self.snapshot, key, int(value))
                        except Exception:
                            setattr(self.snapshot, key, 0)
                    else:
                        setattr(self.snapshot, key, _clean(value, 180))

    def event(self, level: str, message: str) -> None:
        level = str(level or "INFO").upper()
        icon = {"SUCCESS": "✅", "INFO": "ℹ️", "WARNING": "⚠️", "BLOCKED": "⛔", "FINDING": "🔥", "THINKING": "💭"}.get(level, "•")
        rendered = f"{icon} [{level}] {_clean(message, 220)}"
        with self.lock:
            self.events.append(rendered)
            self.events = self.events[-self.max_events :]
            self.snapshot.latest_status = level.lower()
        if self.enabled and self.live_stream and not self.interactive:
            print(_strip_ansi(rendered), flush=True)

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
                "type": _clean(finding_type or "Security Review Lead", 120),
                "severity": severity,
                "description": _clean(description or "Evidence requires analyst review.", 400),
                "url": _clean(url or snap.endpoint, 240),
                "domain": _clean(snap.domain, 120),
                "request_line": _clean(snap.request_line, 220),
                "path": _clean(snap.path, 180),
                "parameter": _clean(parameter or snap.parameters, 220),
                "test_string": _clean(test_string or snap.probe_string, 220),
                "evidence": _clean(evidence or snap.evidence, 800),
                "cvss": _clean(cvss, 80),
                "confidence": _clean(confidence, 80),
                "reproduction": _clean_multiline(reproduction or "Review the generated evidence artifacts and validate only inside the authorized scope."),
                "confirmation": confirmation,
                "recorded_at": time.time(),
            }
            self.finding_details.append(finding)
            self.snapshot.findings = len(self.finding_details)
            self.events.append(f"🔥 [{severity}] {finding['type']}: {finding['description']}")
            self.events = self.events[-self.max_events :]
        return finding

    def finding_count(self) -> int:
        with self.lock:
            return len(self.finding_details)

    def set_target_detail(self, target: str, *, probe_string: str = "—") -> None:
        parts = target_components(target)
        self.update(
            domain=parts["domain"],
            endpoint=parts["endpoint"],
            request_line=parts["request_line"],
            path=parts["path"],
            parameters=parts["parameters"],
            probe_string=probe_string,
        )

    def _elapsed(self) -> str:
        seconds = max(0, int(time.time() - self.snapshot.started_at))
        return f"{seconds // 60:02d}:{seconds % 60:02d}"

    def _bar(self, width: int = 42) -> str:
        total = max(1, self.snapshot.phase_total)
        progress = max(0, min(self.snapshot.phase_progress, total))
        filled = int(width * progress / total)
        return "█" * filled + "░" * (width - filled)

    def _term_width(self) -> int:
        try:
            return max(78, min(120, shutil.get_terminal_size((96, 24)).columns))
        except Exception:
            return 96

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
        preferred = ["cli_final_dashboard_md", "detailed_findings_json", "react_run_md"]
        lines = []
        for key in preferred:
            if key in self.report_paths:
                lines.append(f"{key}: {self.report_paths[key]}")
        for key, value in self.report_paths.items():
            if key not in preferred:
                lines.append(f"{key}: {value}")
        return lines

    def render_text(self, *, final: bool = False, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            events = list(self.events)
        c = (lambda value: value) if color else (lambda value: "")
        width = self._term_width()
        inner = width - 2
        title = "VULNSCOPE ULTIMATE — AUTONOMOUS SECURITY AI"
        subtitle = "Kali CLI Assessment • Full Visibility • Zero-Impact"
        phase_line = f"Target: {snap.target} | Phase: {snap.phase} | Findings: {snap.findings} | Requests: {snap.requests} | Time: {self._elapsed()}"
        lines = [
            f"{c(CYAN)}╔{'═' * inner}╗{c(RESET)}",
            f"{c(CYAN)}║{c(RESET)} {c(MAGENTA)}{title:<{inner - 1}}{c(RESET)}{c(CYAN)}║{c(RESET)}",
            f"{c(CYAN)}║{c(RESET)} {c(YELLOW)}{subtitle:<{inner - 1}}{c(RESET)}{c(CYAN)}║{c(RESET)}",
            f"{c(CYAN)}╚{'═' * inner}╝{c(RESET)}",
            "",
            _clean(phase_line, width + 40),
            "",
            f"{c(MAGENTA)}🧠 THINKING:{c(RESET)} {snap.action}",
            f"{c(BLUE)}🌐 Domain:{c(RESET)} {snap.domain}",
            f"{c(CYAN)}📡 Full Request:{c(RESET)} {snap.request_line}",
            f"{c(CYAN)}🔗 Endpoint:{c(RESET)} {snap.endpoint}",
            f"{c(CYAN)}🗂️  Path:{c(RESET)} {snap.path}",
            f"{c(CYAN)}📝 Parameters:{c(RESET)} {snap.parameters}",
            f"{c(YELLOW)}🔎 Safe string under test:{c(RESET)} {snap.probe_string}",
            f"{c(MAGENTA)}💡 Hypothesis:{c(RESET)} {snap.hypothesis}",
            f"{c(CYAN)}🔍 Evidence snippet:{c(RESET)} {snap.evidence}",
            f"{c(GREEN)}🛡️  Safety:{c(RESET)} {snap.safety_status}",
            "",
            f"{c(YELLOW)}📊 {snap.phase}{c(RESET)} [{self._bar()}] {snap.phase_progress}/{max(1, snap.phase_total)}",
            "",
            f"{c(CYAN)}{'═' * min(width, 96)}{c(RESET)}",
        ]
        if events:
            for entry in reversed(events[-self.max_events :]):
                lines.append(entry)
        else:
            lines.append("ℹ️ [INFO] Waiting for first autonomous action…")
        lines.append(f"{c(CYAN)}{'═' * min(width, 96)}{c(RESET)}")
        footer = "Final Kali CLI dashboard" if final else "Optional live CLI view | Press Ctrl+C to stop safely"
        lines.append(f"{c(CYAN)}{footer}{c(RESET)}")
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
        severity_line = (
            f"{c(BOLD + RED)}CRITICAL:{counts['CRITICAL']}{c(RESET)}  "
            f"{c(RED)}HIGH:{counts['HIGH']}{c(RESET)}  "
            f"{c(YELLOW)}MEDIUM:{counts['MEDIUM']}{c(RESET)}  "
            f"{c(BLUE)}LOW:{counts['LOW']}{c(RESET)}  "
            f"{c(GREEN)}INFO:{counts['INFO']}{c(RESET)}"
        )
        lines = [
            "=" * 80,
            f"{c(CYAN)}╔{'═' * 78}╗{c(RESET)}",
            f"{c(CYAN)}║{c(RESET)} {c(MAGENTA)}VULNSCOPE ULTIMATE — FINAL KALI CLI DASHBOARD{' ' * 28}{c(CYAN)}║{c(RESET)}",
            f"{c(CYAN)}╚{'═' * 78}╝{c(RESET)}",
            f"{c(CYAN)}Target:{c(RESET)} {snap.target}",
            f"{c(CYAN)}Domain:{c(RESET)} {snap.domain}",
            f"{c(CYAN)}Endpoint:{c(RESET)} {snap.endpoint}",
            f"{c(CYAN)}Full Request:{c(RESET)} {snap.request_line}",
            f"{c(CYAN)}Path:{c(RESET)} {snap.path}",
            f"{c(CYAN)}Parameters:{c(RESET)} {snap.parameters}",
            f"{c(CYAN)}Total Time:{c(RESET)} {self._elapsed()}",
            f"{c(CYAN)}Total Findings / Leads:{c(RESET)} {c(GREEN if findings else YELLOW)}{len(findings)}{c(RESET)}",
            f"{c(CYAN)}Confirmed Findings:{c(RESET)} {c(GREEN if confirmed else YELLOW)}{len(confirmed)}{c(RESET)}",
            f"{c(CYAN)}Total Requests / Actions:{c(RESET)} {c(WHITE)}{snap.requests}{c(RESET)}",
            f"{c(CYAN)}Severity Summary:{c(RESET)} {severity_line}",
            "─" * 80,
        ]
        if not findings:
            lines.append(f"{c(YELLOW)}No vulnerabilities were confirmed. No reportable evidence leads were captured within the tested safe vectors.{c(RESET)}")
        else:
            lines.append(f"{c(GREEN)}DETAILED FINDINGS / CONFIRMED AND REVIEW-READY RESULTS{c(RESET)}")
            lines.append("─" * 80)
            for idx, finding in enumerate(findings, 1):
                severity = str(finding.get("severity", "INFO")).upper()
                status = str(finding.get("confirmation", "review_lead")).replace("_", " ").upper()
                severity_color = self._severity_color(severity)
                lines += [
                    "",
                    f"{c(severity_color)}═══ FINDING #{idx} — {severity} — {status} ═══{c(RESET)}",
                    f"{c(YELLOW)}WHAT:{c(RESET)} {finding.get('type')} ({severity})",
                    f"{c(YELLOW)}WHY:{c(RESET)} {finding.get('description')}",
                    f"{c(YELLOW)}WHERE:{c(RESET)} URL: {finding.get('url')}",
                    f"       Domain: {finding.get('domain')}",
                    f"       Request: {finding.get('request_line')}",
                    f"       Path: {finding.get('path')}",
                    f"       Parameter: {finding.get('parameter')}",
                    f"       Safe string under test: {finding.get('test_string')}",
                    f"{c(YELLOW)}TESTED EVIDENCE:{c(RESET)}",
                    f"       Evidence snippet: {finding.get('evidence')}",
                    f"       CVSS Score: {finding.get('cvss')}",
                    f"       Confidence: {finding.get('confidence')}",
                    f"       Confirmation status: {status}",
                    f"{c(YELLOW)}REPRODUCTION / VALIDATION STEPS:{c(RESET)}",
                ]
                for line in str(finding.get("reproduction") or "See evidence above.").splitlines():
                    lines.append(f"       {line}")
                lines.append("─" * 80)
        lines.append("\n--- Final Activity Log ---")
        for entry in events[-self.max_events :]:
            lines.append(entry)
        lines.append("\n--- Report Files ---")
        for entry in self._report_lines():
            lines.append(f"- {entry}")
        lines += [
            "=" * 80,
            f"{c(GREEN)}✅ Final dashboard displayed directly in Kali CLI.{c(RESET)}",
            f"{c(CYAN)}📊 No website dashboard is launched by this feature.{c(RESET)}",
        ]
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def show_final(self) -> None:
        if not self.enabled:
            return
        print(self.final_text(color=self.interactive), flush=True)

    def draw(self, *, final: bool = False) -> None:
        if not self.enabled:
            return
        if self.interactive:
            sys.stdout.write("\033[2J\033[H")
        print(self.final_text(color=self.interactive) if final else self.render_text(final=False, color=self.interactive), flush=True)

    def write_reports(self, out: Path) -> dict[str, str]:
        out.mkdir(parents=True, exist_ok=True)
        with self.lock:
            payload = {
                "snapshot": asdict(self.snapshot),
                "events": list(self.events),
                "findings": [dict(item) for item in self.finding_details],
                "generated_at": time.time(),
                "interface": "kali_cli",
                "dashboard": "ultimate_cli_direct_output",
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
        final_md_path.write_text("# VulnScope Ultimate Kali CLI Final Dashboard\n\n```text\n" + self.final_text(color=False) + "\n```\n", encoding="utf-8")
        return reports
