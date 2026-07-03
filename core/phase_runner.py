#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse


@dataclass
class PhaseResult:
    name: str
    status: str
    started_at: float
    finished_at: float
    elapsed_ms: int
    error: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class PhaseRunner:
    """Crash-safe scan phase runner.

    Every major phase is wrapped so one phase cannot kill the full scan.
    The dashboard always receives start/completed/failed telemetry with the
    current URL/path/endpoint context.
    """

    def __init__(self, *, state: Any, dashboard: Any | None = None, trace: Any | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.trace = trace
        self.results: list[PhaseResult] = []

    def _surface_counts(self) -> dict[str, int]:
        try:
            paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
            api_routes = [item.url for item in self.state.urls.values() if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()]
            return {
                "urls_found": len(self.state.urls),
                "paths_found": len(paths),
                "params_found": len(self.state.params),
                "forms_found": int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)),
                "js_found": int(self.state.stats.get("scripts", 0)),
                "api_routes_found": len(api_routes) + int(self.state.stats.get("javascript_routes", 0)),
            }
        except Exception:
            return {}

    def _emit(self, *, phase: str, action: str, status: str, progress: int, url: str | None = None, evidence: str = "", agent: str = "PhaseRunner", tool: str = "phase_runner") -> None:
        current_url = url or getattr(self.state, "target", "")
        parsed = urlparse(current_url)
        path = parsed.path or "/"
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        try:
            if self.dashboard is not None and hasattr(self.dashboard, "update"):
                self.dashboard.update(
                    phase=phase,
                    phase_progress=progress,
                    current_agent=agent,
                    current_tool=tool,
                    decision=status,
                    action=action,
                    endpoint=current_url,
                    request_line="GET " + path + (("?" + parsed.query) if parsed.query else ""),
                    path=path,
                    parameters=query,
                    domain=parsed.hostname or getattr(self.state, "host", "—"),
                    probe_string="phase-telemetry",
                    evidence=evidence or self.coverage_text(),
                    safety_status="phase watchdog active • same-scope • non-fatal phase failures",
                    requests=int(self.state.stats.get("requests", 0)),
                    findings=len(self.state.findings),
                    **self._surface_counts(),
                )
            if self.dashboard is not None and hasattr(self.dashboard, "event"):
                level = "ERROR" if status == "failed_non_blocking" else "INFO"
                self.dashboard.event(level, f"{phase}: {action}")
        except Exception:
            pass
        try:
            self.state.add_event("INFO" if status != "failed_non_blocking" else "WARNING", f"phase {status}", phase=phase, action=action, endpoint=current_url, evidence=evidence[:500])
        except Exception:
            pass

    def coverage_text(self) -> str:
        try:
            cov = self.state.coverage()
            return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} findings={cov['findings']} timeouts={cov['timeouts']}"
        except Exception:
            return "coverage unavailable"

    def run(self, name: str, fn: Callable[[], Any], *, progress_start: int, progress_end: int, url: str | None = None, agent: str = "PhaseRunner", tool: str = "phase_runner", required: bool = False) -> PhaseResult:
        started = time.time()
        self._emit(phase=name, action="starting", status="running", progress=progress_start, url=url, agent=agent, tool=tool)
        try:
            data_raw = fn()
            data = asdict(data_raw) if hasattr(data_raw, "__dataclass_fields__") else (dict(data_raw) if isinstance(data_raw, dict) else {"result": str(data_raw)[:1000]})
            result = PhaseResult(name=name, status="completed", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), data=data)
            self.results.append(result)
            self._emit(phase=name, action="completed", status="completed", progress=progress_end, url=url, evidence=self.coverage_text(), agent=agent, tool=tool)
            return result
        except Exception as exc:
            status = "failed_required" if required else "failed_non_blocking"
            result = PhaseResult(name=name, status=status, started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), error=str(exc)[:1000])
            self.results.append(result)
            self._emit(phase=name, action=f"failed: {str(exc)[:180]}", status="failed_non_blocking", progress=progress_end, url=url, evidence=str(exc)[:500], agent=agent, tool=tool)
            if required:
                raise
            return result

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.results),
            "completed": sum(1 for item in self.results if item.status == "completed"),
            "failed_non_blocking": sum(1 for item in self.results if item.status == "failed_non_blocking"),
            "failed_required": sum(1 for item in self.results if item.status == "failed_required"),
            "phases": [asdict(item) for item in self.results],
        }
