from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AgentResult:
    agent: str
    status: str = "completed"
    candidates: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    next_actions: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    manual_validation_required: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "status": self.status,
            "candidates": self.candidates,
            "evidence": self.evidence,
            "next_actions": self.next_actions,
            "confidence": self.confidence,
            "manual_validation_required": self.manual_validation_required,
            "notes": self.notes,
        }


class BaseReviewAgent:
    name = "BaseReviewAgent"

    def run(self, evidence: dict[str, Any]) -> AgentResult:
        raise NotImplementedError


def load_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def collect_urls(evidence: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for key in ("archived_urls", "endpoints", "urls"):
        value = evidence.get(key, []) if isinstance(evidence, dict) else []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    urls.append(item)
                elif isinstance(item, dict):
                    url = item.get("url") or item.get("endpoint")
                    if url:
                        urls.append(str(url))
    for item in evidence.get("high_value_urls", []) if isinstance(evidence, dict) else []:
        if isinstance(item, dict) and item.get("url"):
            urls.append(str(item["url"]))
    return sorted(set(urls))
