from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

HISTORY_PATH = Path("reports/output/agentic/run-history.jsonl")


def log_event(event_type: str, payload: dict[str, Any]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.utcnow().isoformat() + "Z", "event_type": event_type, "payload": payload}
    with HISTORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_history(limit: int = 50) -> list[dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    rows = []
    for line in HISTORY_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows
