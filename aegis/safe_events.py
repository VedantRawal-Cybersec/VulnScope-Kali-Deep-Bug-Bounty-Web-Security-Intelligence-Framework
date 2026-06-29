from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

OUT_DIR = Path("reports/output/aegis/events")
OUT_FILE = OUT_DIR / "safe-events.jsonl"


def record(event_type: str, payload: dict[str, Any] | None = None, level: str = "info") -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    item = {"ts": time.time(), "level": level, "type": event_type, "payload": payload or {}}
    with OUT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    return item


def read_recent(limit: int = 100) -> list[dict[str, Any]]:
    if not OUT_FILE.exists():
        return []
    rows = []
    for line in OUT_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows
