from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

PHASES = [
    "P0_INIT",
    "P1_SCOPE_CONFIRM",
    "P2_TARGET_INGEST",
    "P3_PASSIVE_RECON",
    "P4_APP_PROFILE",
    "P5_AUTH_CONTEXT",
    "P6_AGENT_PLANNING",
    "P7_SPECIALIST_REVIEW",
    "P8_EVIDENCE_VALIDATION",
    "P9_REPORTABILITY_SCORING",
    "P10_FINAL_REPORT",
]


@dataclass
class AssessmentState:
    target: str
    mode: str = "bounty"
    current_phase: str = "P0_INIT"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    completed_phases: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    agent_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    safety_notes: list[str] = field(default_factory=lambda: [
        "Authorized in-scope assessment only.",
        "No destructive actions.",
        "No credential collection or third-party account use.",
        "No evidence = no confirmed vulnerability.",
    ])

    def mark_phase(self, phase: str) -> None:
        self.current_phase = phase
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def add_artifact(self, name: str, path: str) -> None:
        self.artifacts[name] = path
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def add_agent_result(self, agent_name: str, result: dict[str, Any]) -> None:
        self.agent_results[agent_name] = result
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def add_decision(self, decision: dict[str, Any]) -> None:
        self.decisions.append(decision)
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_file(cls, path: Path) -> "AssessmentState":
        data = json.loads(path.read_text(encoding="utf-8"))
        state = cls(target=data["target"], mode=data.get("mode", "bounty"))
        state.current_phase = data.get("current_phase", "P0_INIT")
        state.created_at = data.get("created_at", state.created_at)
        state.updated_at = data.get("updated_at", state.updated_at)
        state.completed_phases = data.get("completed_phases", [])
        state.artifacts = data.get("artifacts", {})
        state.agent_results = data.get("agent_results", {})
        state.decisions = data.get("decisions", [])
        state.safety_notes = data.get("safety_notes", state.safety_notes)
        return state
