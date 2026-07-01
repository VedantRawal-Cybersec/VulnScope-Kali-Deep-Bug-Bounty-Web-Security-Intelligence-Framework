#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target


class StateManager:
    """Persist ReAct loop state without touching the target."""

    def __init__(self, target: str):
        self.target = normalize_target(target)
        self.out_dir = cai_output_dir(self.target)
        self.path = self.out_dir / "react-state.json"
        self.events_path = self.out_dir / "react-events.jsonl"
        self.state: dict[str, Any] = self.load()

    def load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
        return {
            "target": self.target,
            "created_at": time.time(),
            "updated_at": time.time(),
            "turn": 0,
            "completed": [],
            "findings": [],
            "decisions": [],
            "observations": [],
            "stopped": False,
            "stop_reason": "",
        }

    def save(self) -> None:
        self.state["updated_at"] = time.time()
        write_json(self.path, self.state)

    def event(self, event_type: str, payload: dict[str, Any]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        row = {"target": self.target, "event_type": event_type, "payload": payload, "created_at": time.time()}
        with self.events_path.open("a", encoding="utf-8", errors="ignore") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    def mark_completed(self, action: str, observation: dict[str, Any]) -> None:
        completed = self.state.setdefault("completed", [])
        if action not in completed:
            completed.append(action)
        self.state.setdefault("observations", []).append({"action": action, "observation": observation, "created_at": time.time()})
        self.event("action_completed", {"action": action, "observation": observation})
        self.save()

    def decision(self, payload: dict[str, Any]) -> None:
        self.state.setdefault("decisions", []).append(payload)
        self.event("brain_decision", payload)
        self.save()

    def add_finding(self, payload: dict[str, Any]) -> None:
        self.state.setdefault("findings", []).append(payload)
        self.event("finding_observed", payload)
        self.save()

    def stop(self, reason: str) -> None:
        self.state["stopped"] = True
        self.state["stop_reason"] = reason
        self.event("loop_stopped", {"reason": reason})
        self.save()

    def write_report(self) -> dict[str, Any]:
        self.save()
        checkpoint = {
            "checkpoint": "react-state",
            "name": "Safe ReAct State",
            "status": "completed",
            "target": self.target,
            "summary": {
                "turn": self.state.get("turn", 0),
                "completed": len(self.state.get("completed", [])),
                "findings": len(self.state.get("findings", [])),
                "stopped": self.state.get("stopped", False),
            },
            "reports": {"json": str(self.path), "markdown": str(self.out_dir / "react-state.md")},
            "generated_at": time.time(),
        }
        write_json(self.out_dir / "checkpoint-react-state.json", checkpoint)
        lines = [
            "# VulnScope Safe ReAct State",
            "",
            f"Target: `{self.target}`",
            f"Turns: `{self.state.get('turn', 0)}`",
            f"Completed actions: `{len(self.state.get('completed', []))}`",
            f"Findings observed: `{len(self.state.get('findings', []))}`",
            f"Stopped: `{self.state.get('stopped', False)}`",
            f"Stop reason: `{self.state.get('stop_reason', '')}`",
            "",
            "## Completed",
        ]
        for item in self.state.get("completed", []):
            lines.append(f"- `{item}`")
        write_markdown(self.out_dir / "react-state.md", lines)
        return checkpoint
