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
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
GRAY = "\033[90m"

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|authorization|cookie)=([^\s&]+)"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=-]{12,}"),
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
    for pattern in SECRET_PATTERNS:
        def repl(match: re.Match[str]) -> str:
            if match.lastindex and match.lastindex >= 2:
                return f"{match.group(1)}=<redacted>"
            if match.lastindex and match.lastindex >= 1:
                return f"{match.group(1)}<redacted>"
            return "<redacted>"
        text = pattern.sub(repl, text)
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
        "path": path,
        "parameters": query,
        "request_line": request_line,
    }


class LiveDashboard:
    """Terminal dashboard for transparent, zero-impact autonomous execution."""

    def __init__(self, target: str, *, max_turns: int = 0, enabled: bool = True, refresh_interval: float = 0.5, interactive: bool | None = None) -> None:
        parts = target_components(target)
        self.snapshot = LiveSnapshot(
            target=_clean(parts["target"], 180),
            max_turns=max_turns,
            domain=_clean(parts["domain"], 100),
            endpoint=_clean(parts["endpoint"], 180),
            path=_clean(parts["path"], 140),
            parameters=_clean(parts["parameters"], 160),
        )
        self.enabled = bool(enabled) and os.getenv("VULNSCOPE_NO_LIVE_DASHBOARD", "0") != "1"
        self.interactive = sys.stdout.isatty() if interactive is None else bool(interactive)
        self.refresh_interval = max(float(refresh_interval), 0.2)
        self.lock = threading.Lock()
        self.events: list[str] = []
        self.max_events = 10
        self.running = False
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.enabled:
            return
        self.running = True
        if self.interactive:
            self.thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self.thread.start()
        else:
            print("[live-dashboard] started", flush=True)

    def _refresh_loop(self) -> None:
        while self.running:
            self.draw(final=False)
            time.sleep(self.refresh_interval)

    def stop(self, *, final: bool = True) -> None:
        if not self.enabled:
            return
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        if final:
            self.draw(final=True)

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
        if self.enabled and not self.interactive:
            print(_strip_ansi(rendered), flush=True)

    def set_target_detail(self, target: str, *, probe_string: str = "—") -> None:
        parts = target_components(target)
        self.update(
            domain=parts["domain"],
            endpoint=parts["endpoint"],
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

    def render_text(self, *, final: bool = False, color: bool = True) -> str:
        with self.lock:
            snap = LiveSnapshot(**asdict(self.snapshot))
            events = list(self.events)
        c = (lambda value: value) if color else (lambda value: "")
        width = self._term_width()
        inner = width - 2
        title = "VULNSCOPE — AUTONOMOUS SECURITY AI"
        subtitle = "Live Assessment • Full Visibility • Zero-Impact"
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
            f"{c(CYAN)}🔗 Endpoint:{c(RESET)} {snap.endpoint}",
            f"{c(CYAN)}🗂️  Path:{c(RESET)} {snap.path}",
            f"{c(CYAN)}📝 Parameters:{c(RESET)} {snap.parameters}",
            f"{c(YELLOW)}🔎 String under test:{c(RESET)} {snap.probe_string}",
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
        footer = "Final dashboard" if final else "Press Ctrl+C to stop scan | All findings are evidence-scored"
        lines.append(f"{c(CYAN)}{footer}{c(RESET)}")
        text = "\n".join(lines)
        return text if color else _strip_ansi(text)

    def draw(self, *, final: bool = False) -> None:
        if not self.enabled:
            return
        if self.interactive:
            sys.stdout.write("\033[2J\033[H")
        print(self.render_text(final=final, color=self.interactive), flush=True)

    def write_reports(self, out: Path) -> dict[str, str]:
        out.mkdir(parents=True, exist_ok=True)
        with self.lock:
            payload = {"snapshot": asdict(self.snapshot), "events": list(self.events), "generated_at": time.time()}
        json_path = out / "live-dashboard.json"
        md_path = out / "live-dashboard.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        md_path.write_text("# VulnScope Live Dashboard\n\n```text\n" + self.render_text(final=True, color=False) + "\n```\n", encoding="utf-8")
        return {"live_dashboard_json": str(json_path), "live_dashboard_md": str(md_path)}
