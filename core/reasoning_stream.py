#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target


@dataclass
class ReasoningEvent:
    event_id: str
    timestamp: float
    turn_id: str
    agent: str
    observation: str
    hypothesis: str
    decision: str
    selected_tool: str
    safety: str
    evidence_summary: str
    next_action: str
    progress_percent: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReasoningStream:
    """Streams concise public reasoning summaries to the CLI/dashboard.

    This intentionally emits short observable reasoning summaries, not hidden chain-of-thought.
    """

    def __init__(self, target: str, *, dashboard: Any | None = None, trace: Any | None = None) -> None:
        self.target = normalize_target(target)
        self.dashboard = dashboard
        self.trace = trace
        self.events: list[ReasoningEvent] = []
        self.out = cai_output_dir(self.target)
        self.out.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.out / "reasoning-stream.jsonl"

    def publish(
        self,
        *,
        agent: str,
        observation: str,
        hypothesis: str,
        decision: str,
        selected_tool: str,
        safety: str,
        evidence_summary: str = "",
        next_action: str = "",
        turn_id: str = "",
        progress_percent: int = 0,
    ) -> ReasoningEvent:
        event = ReasoningEvent(
            event_id="reason_" + uuid.uuid4().hex[:10],
            timestamp=time.time(),
            turn_id=turn_id or "turn_" + uuid.uuid4().hex[:8],
            agent=agent,
            observation=str(observation)[:500],
            hypothesis=str(hypothesis)[:500],
            decision=str(decision)[:500],
            selected_tool=str(selected_tool)[:120],
            safety=str(safety)[:500],
            evidence_summary=str(evidence_summary)[:700],
            next_action=str(next_action)[:500],
            progress_percent=int(progress_percent),
        )
        self.events.append(event)
        with self.jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        line = f"{agent}: {event.observation} → {event.decision}"
        if self.dashboard is not None:
            if hasattr(self.dashboard, "event"):
                self.dashboard.event("THINKING", line)
            if hasattr(self.dashboard, "trace"):
                self.dashboard.trace(line)
            if hasattr(self.dashboard, "update"):
                self.dashboard.update(
                    current_agent=agent,
                    current_tool=selected_tool,
                    decision=decision,
                    action=next_action or decision,
                    hypothesis=hypothesis,
                    evidence=evidence_summary or observation,
                    safety_status=safety,
                    phase_progress=progress_percent,
                )
        if self.trace is not None and hasattr(self.trace, "log"):
            self.trace.log(
                turn_id=event.turn_id,
                agent_name=agent,
                tool_name=selected_tool,
                phase="Reasoning",
                status="public_reasoning",
                target_url=self.target,
                message=line,
                evidence_summary=event.evidence_summary,
                progress_percent=progress_percent,
            )
        return event

    def stream_text(self, *, agent: str, text: str, selected_tool: str = "llm_gateway", turn_id: str = "", progress_percent: int = 0) -> None:
        chunks = [part.strip() for part in str(text).replace("\r", "").split("\n") if part.strip()]
        for chunk in chunks[:12]:
            self.publish(
                agent=agent,
                observation="LLM public reasoning update",
                hypothesis="model-provided concise rationale",
                decision=chunk[:500],
                selected_tool=selected_tool,
                safety="LLM output is advisory and must pass guardrails before execution",
                next_action="continue safe deterministic scan",
                turn_id=turn_id,
                progress_percent=progress_percent,
            )

    def write_reports(self) -> dict[str, str]:
        json_path = self.out / "reasoning-stream.json"
        md_path = self.out / "reasoning-stream.md"
        write_json(json_path, [item.to_dict() for item in self.events])
        lines = ["# VulnScope Public Reasoning Stream", "", f"Target: `{self.target}`", ""]
        for item in self.events[-300:]:
            lines.append(f"- `{item.turn_id}` **{item.agent}** observation={item.observation} decision={item.decision} tool=`{item.selected_tool}` safety={item.safety}")
        write_markdown(md_path, lines)
        return {"reasoning_stream_jsonl": str(self.jsonl), "reasoning_stream_json": str(json_path), "reasoning_stream_md": str(md_path)}
