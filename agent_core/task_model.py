from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AgentTask:
    task_id: str
    agent: str
    goal: str
    inputs: dict[str, Any] = field(default_factory=dict)
    risk_level: str = "review-only"
    requires_human: bool = False
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentObservation:
    task_id: str
    agent: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    next_tasks: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
