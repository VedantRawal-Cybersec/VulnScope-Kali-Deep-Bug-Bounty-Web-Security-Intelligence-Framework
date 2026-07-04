#!/usr/bin/env python3
from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any


class AutonomousPlanner:
    def __init__(self, q_table_path: str | Path = "q_table.json", learning_rate: float = 0.25, discount: float = 0.85, exploration: float = 0.15) -> None:
        self.q_table_path = Path(q_table_path)
        self.learning_rate = learning_rate
        self.discount = discount
        self.exploration = exploration
        self.q_table: dict[str, dict[str, float]] = {}
        self.load()

    def load(self) -> None:
        if not self.q_table_path.exists():
            self.q_table = {}
            return
        try:
            self.q_table = json.loads(self.q_table_path.read_text(encoding="utf-8"))
        except Exception:
            self.q_table = {}

    def save(self) -> None:
        self.q_table_path.write_text(json.dumps(self.q_table, indent=2, ensure_ascii=False), encoding="utf-8")

    def state_key(self, context: dict[str, Any]) -> str:
        tech = context.get("tech_stack") or []
        if isinstance(tech, str):
            tech = [tech]
        mode = str(context.get("mode", "bugbounty"))
        surface = context.get("surface", {}) or {}
        density = "no_params"
        try:
            params = int(surface.get("params", 0))
        except Exception:
            params = 0
        if params > 50:
            density = "many_params"
        elif params > 0:
            density = "some_params"
        stack = ",".join(sorted(str(item).lower() for item in tech)) or "unknown"
        return f"{mode}|{stack}|{density}"

    def choose_tool(self, context: dict[str, Any], available_tools: list[str], *, aggressive: bool = False) -> str:
        if not available_tools:
            return ""
        key = self.state_key(context)
        self.q_table.setdefault(key, {})
        for tool in available_tools:
            self.q_table[key].setdefault(tool, 0.0)
        epsilon = self.exploration * (0.5 if aggressive else 1.0)
        if random.random() < epsilon:
            return random.choice(available_tools)
        return max(available_tools, key=lambda tool: self.q_table[key].get(tool, 0.0))

    def reward_from_findings(self, findings: list[dict[str, Any]]) -> float:
        reward = 0.0
        for finding in findings:
            try:
                confidence = float(finding.get("confidence", finding.get("confidence_score", 0)) or 0)
            except Exception:
                confidence = 0.0
            if confidence > 1:
                confidence = confidence / 100.0
            severity = str(finding.get("severity") or "INFO").upper()
            if confidence >= 0.7:
                reward += {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 2.0, "INFO": 0.5}.get(severity, 1.0)
        return reward

    def update(self, context: dict[str, Any], tool: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        key = self.state_key(context)
        self.q_table.setdefault(key, {})
        self.q_table[key].setdefault(tool, 0.0)
        reward = self.reward_from_findings(findings)
        old_value = self.q_table[key][tool]
        best_future = max(self.q_table[key].values() or [0.0])
        new_value = old_value + self.learning_rate * (reward + self.discount * best_future - old_value)
        self.q_table[key][tool] = round(new_value, 6)
        self.save()
        return {"time": time.time(), "state": key, "tool": tool, "reward": reward, "old_value": old_value, "new_value": new_value}

    def update_from_feedback(self, context: dict[str, Any], tool: str, accepted: int, rejected: int) -> dict[str, Any]:
        pseudo_findings = []
        for _ in range(max(0, accepted)):
            pseudo_findings.append({"severity": "HIGH", "confidence": 0.9})
        for _ in range(max(0, rejected)):
            pseudo_findings.append({"severity": "INFO", "confidence": 0.1})
        return self.update(context, tool, pseudo_findings)
