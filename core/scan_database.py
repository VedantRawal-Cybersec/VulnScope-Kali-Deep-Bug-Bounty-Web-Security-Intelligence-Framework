#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class ScanDatabase:
    """SQLite persistence for scan runs and generated artifacts."""

    def __init__(self, path: str = "reports/output/vulnscope.sqlite3") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def migrate(self) -> None:
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS scan_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, host TEXT, mode TEXT, created_at TEXT, coverage_json TEXT, stats_json TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS scan_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, key TEXT, path TEXT, created_at TEXT, FOREIGN KEY(run_id) REFERENCES scan_runs(id))")
            conn.execute("CREATE TABLE IF NOT EXISTS scan_items (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, item_type TEXT, value TEXT, metadata_json TEXT, FOREIGN KEY(run_id) REFERENCES scan_runs(id))")

    def record(self, *, state: Any, reports: dict[str, str] | None = None) -> dict[str, Any]:
        self.migrate()
        coverage = state.coverage() if hasattr(state, "coverage") else {}
        stats = getattr(state, "stats", {}) or {}
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.connect() as conn:
            cur = conn.execute("INSERT INTO scan_runs(target, host, mode, created_at, coverage_json, stats_json) VALUES(?,?,?,?,?,?)", (getattr(state, "target", ""), getattr(state, "host", ""), stats.get("scan_mode", ""), created, json.dumps(coverage, ensure_ascii=False), json.dumps(stats, ensure_ascii=False)))
            run_id = int(cur.lastrowid)
            for key, path in (reports or {}).items():
                conn.execute("INSERT INTO scan_reports(run_id, key, path, created_at) VALUES(?,?,?,?)", (run_id, str(key), str(path), created))
            for url in getattr(state, "urls", {}) or {}:
                conn.execute("INSERT INTO scan_items(run_id, item_type, value, metadata_json) VALUES(?,?,?,?)", (run_id, "url", str(url), "{}"))
            for param in (getattr(state, "params", {}) or {}).values():
                conn.execute("INSERT INTO scan_items(run_id, item_type, value, metadata_json) VALUES(?,?,?,?)", (run_id, "parameter", getattr(param, "name", ""), json.dumps(getattr(param, "__dict__", {}), ensure_ascii=False, default=str)))
        return {"database": str(self.path), "run_id": run_id}
