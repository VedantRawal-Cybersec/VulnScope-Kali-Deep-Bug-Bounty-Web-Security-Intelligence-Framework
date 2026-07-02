#!/usr/bin/env python3
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from core.autonomous_scan_engine import AutonomousScanEngine


@dataclass
class ScanHandle:
    scan_id: str
    target: str
    status: str = "queued"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    stop_requested: bool = False
    thread: threading.Thread | None = None


SCANS: dict[str, ScanHandle] = {}


def start_scan(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    options = dict(options or {})
    scan_id = options.pop("scan_id", "scan_" + uuid.uuid4().hex[:10])
    handle = ScanHandle(scan_id=scan_id, target=target)
    SCANS[scan_id] = handle

    def runner() -> None:
        handle.status = "running"
        try:
            engine = AutonomousScanEngine(target, live_dashboard=False, **options)
            handle.payload = engine.run()
            handle.status = str(handle.payload.get("status") or "completed")
        except Exception as exc:
            handle.status = "failed"
            handle.error = str(exc)[:1000]
        finally:
            handle.finished_at = time.time()

    thread = threading.Thread(target=runner, daemon=True)
    handle.thread = thread
    thread.start()
    return {"scan_id": scan_id, "status": handle.status, "target": target}


def get_scan_status(scan_id: str) -> dict[str, Any]:
    handle = SCANS.get(scan_id)
    if not handle:
        return {"scan_id": scan_id, "status": "not_found"}
    return {"scan_id": scan_id, "status": handle.status, "target": handle.target, "started_at": handle.started_at, "finished_at": handle.finished_at, "error": handle.error, "summary": handle.payload.get("coverage", {}) if handle.payload else {}}


def get_scan_events(scan_id: str) -> list[dict[str, Any]]:
    handle = SCANS.get(scan_id)
    if not handle:
        return []
    reports = handle.payload.get("reports", {}) if handle.payload else {}
    return [{"scan_id": scan_id, "status": handle.status, "reports": reports, "error": handle.error}]


def get_tool_status(scan_id: str) -> dict[str, Any]:
    handle = SCANS.get(scan_id)
    if not handle:
        return {"scan_id": scan_id, "status": "not_found", "tools": {}}
    return {"scan_id": scan_id, "status": handle.status, "tools": handle.payload.get("tool_status", {}) if handle.payload else {}}


def get_findings(scan_id: str) -> list[dict[str, Any]]:
    handle = SCANS.get(scan_id)
    if not handle:
        return []
    return list(handle.payload.get("findings", []) if handle.payload else [])


def get_report(scan_id: str) -> dict[str, Any]:
    handle = SCANS.get(scan_id)
    if not handle:
        return {"scan_id": scan_id, "status": "not_found"}
    return {"scan_id": scan_id, "status": handle.status, "reports": handle.payload.get("reports", {}) if handle.payload else {}}


def stop_scan(scan_id: str) -> dict[str, Any]:
    handle = SCANS.get(scan_id)
    if not handle:
        return {"scan_id": scan_id, "status": "not_found"}
    handle.stop_requested = True
    return {"scan_id": scan_id, "status": handle.status, "message": "stop requested; running request will finish safely"}


def run_diagnostics() -> dict[str, Any]:
    return {"status": "ok", "backend": "colab-compatible in-process API", "functions": ["start_scan", "get_scan_status", "get_scan_events", "get_tool_status", "get_findings", "get_report", "stop_scan", "run_diagnostics"]}
