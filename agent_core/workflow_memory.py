from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MEMORY_DIR = Path("reports/output/agent_core")
MEMORY_FILE = MEMORY_DIR / "workflow-memory.json"


def load_memory() -> dict[str, Any]:
    if not MEMORY_FILE.exists():
        return {"targets": {}, "lessons": [], "version": 1}
    try:
        return json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"targets": {}, "lessons": [], "version": 1}


def save_memory(memory: dict[str, Any]) -> None:
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY_FILE.write_text(json.dumps(memory, indent=2, ensure_ascii=False), encoding="utf-8")


def remember_target(target: str, summary: dict[str, Any]) -> None:
    memory = load_memory()
    memory.setdefault("targets", {})[target] = summary
    save_memory(memory)


def add_lesson(text: str, source: str = "workflow") -> None:
    memory = load_memory()
    memory.setdefault("lessons", []).append({"source": source, "text": text})
    save_memory(memory)
