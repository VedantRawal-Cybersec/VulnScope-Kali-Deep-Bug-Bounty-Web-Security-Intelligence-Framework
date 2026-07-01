#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, normalize_target

DB_PATH = Path("reports/output/cai-superior/agentic/agentic_memory.db")
EVENT_LOG = Path("reports/output/cai-superior/agentic/short-term-events.jsonl")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS memory_events (id TEXT PRIMARY KEY, host TEXT, event_type TEXT, payload TEXT, created_at REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS endpoint_state (host TEXT, endpoint TEXT, status TEXT, last_seen REAL, notes TEXT, PRIMARY KEY(host, endpoint))")
    conn.execute("CREATE TABLE IF NOT EXISTS hypothesis_state (host TEXT, hypothesis_id TEXT PRIMARY KEY, status TEXT, priority REAL, payload TEXT, updated_at REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS vector_notes (id TEXT PRIMARY KEY, host TEXT, text TEXT, tags TEXT, created_at REAL)")
    return conn


def _hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def record_event(target: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    event = {"target": target, "host": host, "event_type": event_type, "payload": payload, "created_at": time.time()}
    event_id = _hash(event)
    event["id"] = event_id
    conn = _connect()
    conn.execute("INSERT OR REPLACE INTO memory_events VALUES (?, ?, ?, ?, ?)", (event_id, host, event_type, json.dumps(payload, ensure_ascii=False), event["created_at"]))
    conn.commit()
    conn.close()
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOG.open("a", encoding="utf-8", errors="ignore") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def ingest_scan_outputs(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    out_dir = cai_output_dir(target)
    conn = _connect()
    endpoints_added = 0
    hypotheses_added = 0
    notes_added = 0

    inv_path = out_dir / "input-inventory.json"
    try:
        inv = json.loads(inv_path.read_text(encoding="utf-8", errors="ignore"))
        for endpoint in inv.get("endpoints", []) or []:
            url = str(endpoint.get("url") or endpoint.get("path_template") or "")
            if not url:
                continue
            conn.execute("INSERT OR REPLACE INTO endpoint_state VALUES (?, ?, ?, ?, ?)", (host, url, "observed", time.time(), json.dumps(endpoint, ensure_ascii=False)[:2000]))
            endpoints_added += 1
    except Exception as exc:
        record_event(target, "memory_ingest_error", handled_error(component="agentic_memory", action="ingest_input_inventory", error=exc))

    matrix_path = out_dir / "hypothesis-matrix.json"
    try:
        matrix = json.loads(matrix_path.read_text(encoding="utf-8", errors="ignore"))
        for item in matrix.get("hypotheses", []) or []:
            hid = _hash(item)
            conn.execute("INSERT OR REPLACE INTO hypothesis_state VALUES (?, ?, ?, ?, ?, ?)", (host, hid, "pending_or_reviewed", float(item.get("priority_score") or 0.0), json.dumps(item, ensure_ascii=False), time.time()))
            hypotheses_added += 1
    except Exception as exc:
        record_event(target, "memory_ingest_error", handled_error(component="agentic_memory", action="ingest_hypothesis_matrix", error=exc))

    for name in ["evidence-scoring.json", "prioritized-findings.json", "adaptive-risk.json", "business-workflow-review.json"]:
        path = out_dir / name
        try:
            if not path.exists():
                continue
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            note_text = f"{name}: {json.dumps(payload.get('summary', {}), ensure_ascii=False)}"
            nid = _hash({"host": host, "name": name, "text": note_text})
            conn.execute("INSERT OR REPLACE INTO vector_notes VALUES (?, ?, ?, ?, ?)", (nid, host, note_text, name, time.time()))
            notes_added += 1
        except Exception as exc:
            record_event(target, "memory_ingest_error", handled_error(component="agentic_memory", action="ingest_" + name, error=exc))
    conn.commit()
    total_events = conn.execute("SELECT COUNT(*) FROM memory_events WHERE host=?", (host,)).fetchone()[0]
    total_endpoints = conn.execute("SELECT COUNT(*) FROM endpoint_state WHERE host=?", (host,)).fetchone()[0]
    total_hypotheses = conn.execute("SELECT COUNT(*) FROM hypothesis_state WHERE host=?", (host,)).fetchone()[0]
    total_notes = conn.execute("SELECT COUNT(*) FROM vector_notes WHERE host=?", (host,)).fetchone()[0]
    conn.close()
    return {
        "target": target,
        "generated_at": time.time(),
        "memory_database": str(DB_PATH),
        "summary": {
            "events": total_events,
            "endpoints_tracked": total_endpoints,
            "hypotheses_tracked": total_hypotheses,
            "notes_tracked": total_notes,
            "endpoints_added_this_run": endpoints_added,
            "hypotheses_added_this_run": hypotheses_added,
            "notes_added_this_run": notes_added,
        },
        "safety": {"new_requests_sent": False, "state_change": False},
    }


def write_memory_report(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out = cai_output_dir(target)
    write_json(out / "agentic-memory.json", payload)
    checkpoint = {"checkpoint": "agentic-memory", "name": "Agentic Memory", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out / "agentic-memory.json"), "markdown": str(out / "agentic-memory.md")}, "generated_at": time.time()}
    write_json(out / "checkpoint-agentic-memory.json", checkpoint)
    lines = ["# CAI Agentic Memory", "", f"Target: `{target}`", f"Database: `{payload.get('memory_database')}`", "", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```"]
    write_markdown(out / "agentic-memory.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI agentic short/long-term memory")
    parser.add_argument("--target", required=True)
    parser.add_argument("--event-type", default="")
    parser.add_argument("--payload-json", default="{}")
    args = parser.parse_args()
    if args.event_type:
        payload = record_event(args.target, args.event_type, json.loads(args.payload_json))
    else:
        payload = ingest_scan_outputs(args.target)
        write_memory_report(args.target, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
