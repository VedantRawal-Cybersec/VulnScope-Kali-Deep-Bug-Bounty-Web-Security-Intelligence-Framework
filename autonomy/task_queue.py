from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

QUEUE_DIR = Path("reports/output/autonomy")
QUEUE_FILE = QUEUE_DIR / "task-queue.json"


@dataclass
class AutoTask:
    task_id: str
    action: str
    target: str
    risk_level: str
    status: str = "pending"
    created_at: float = 0.0
    updated_at: float = 0.0
    inputs: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data["created_at"]:
            data["created_at"] = time.time()
        data["updated_at"] = time.time()
        return data


def load_queue() -> list[dict[str, Any]]:
    if not QUEUE_FILE.exists():
        return []
    try:
        return json.loads(QUEUE_FILE.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []


def save_queue(tasks: list[dict[str, Any]]) -> Path:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_FILE.write_text(json.dumps(tasks, indent=2, ensure_ascii=False), encoding="utf-8")
    return QUEUE_FILE


def enqueue(task: AutoTask) -> dict[str, Any]:
    tasks = load_queue()
    item = task.to_dict()
    tasks.append(item)
    save_queue(tasks)
    return item


def update_task(task_id: str, **updates: Any) -> None:
    tasks = load_queue()
    for task in tasks:
        if task.get("task_id") == task_id:
            task.update(updates)
            task["updated_at"] = time.time()
            break
    save_queue(tasks)
