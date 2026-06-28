from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path("reports/output/agentic/evidence-index.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target TEXT,
    mode TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    summary TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    decision_type TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def create_run(target: str, mode: str, notes: str = "") -> int:
    conn = connect()
    cur = conn.execute(
        "INSERT INTO runs(created_at,target,mode,notes) VALUES(?,?,?,?)",
        (datetime.utcnow().isoformat() + "Z", target, mode, notes),
    )
    conn.commit()
    run_id = int(cur.lastrowid)
    conn.close()
    return run_id


def add_artifact(run_id: int, artifact_type: str, path: str, summary: str = "") -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO artifacts(run_id,artifact_type,path,summary,created_at) VALUES(?,?,?,?,?)",
        (run_id, artifact_type, path, summary, datetime.utcnow().isoformat() + "Z"),
    )
    conn.commit()
    conn.close()


def add_decision(run_id: int, decision_type: str, detail: dict[str, Any]) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO decisions(run_id,decision_type,detail_json,created_at) VALUES(?,?,?,?)",
        (run_id, decision_type, json.dumps(detail, ensure_ascii=False), datetime.utcnow().isoformat() + "Z"),
    )
    conn.commit()
    conn.close()
