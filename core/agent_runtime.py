#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from core.agentic_framework import AgentRegistry, HandoffManager, TraceLogger, TurnManager
from core.reasoning_stream import ReasoningStream
from core.tool_router import ToolRouter


@dataclass
class AgentTurn:
    turn_id: str
    agent: str
    observation: str
    decision: str
    selected_tool: str
    handoff_to: str = ""
    status: str = "completed"
    started_at: float = field(default_factory=time.time)
    finished_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentRuntime:
    """Small CAI-style runtime that coordinates agent turns, tool routing, and handoffs."""

    def __init__(self, *, target: str, dashboard: Any | None = None, trace: TraceLogger | None = None, reasoning: ReasoningStream | None = None) -> None:
        self.target = target
        self.registry = AgentRegistry()
        self.turns = TurnManager()
        self.trace = trace or TraceLogger(target, scan_id="runtime")
        self.handoffs = HandoffManager(self.trace, dashboard)
        self.reasoning = reasoning
        self.router = ToolRouter()
        self.history: list[AgentTurn] = []

    def run_turn(
        self,
        *,
        agent: str,
        observation: str,
        decision: str,
        selected_tool: str,
        phase: str,
        handoff_to: str = "",
        safety: str = "approved by deterministic guardrails",
        evidence_summary: str = "",
        progress_percent: int = 0,
    ) -> AgentTurn:
        turn_id = self.turns.next_turn()
        started = time.time()
        self.trace.log(turn_id=turn_id, agent_name=agent, tool_name=selected_tool, phase=phase, status="running", target_url=self.target, message=observation, evidence_summary=evidence_summary, progress_percent=progress_percent)
        if self.reasoning is not None:
            self.reasoning.publish(agent=agent, observation=observation, hypothesis=f"{agent} selected {selected_tool}", decision=decision, selected_tool=selected_tool, safety=safety, evidence_summary=evidence_summary, next_action=handoff_to or decision, turn_id=turn_id, progress_percent=progress_percent)
        if handoff_to:
            self.handoffs.handoff(agent, handoff_to, phase=phase, message=decision, target_url=self.target, progress_percent=progress_percent)
        turn = AgentTurn(turn_id, agent, observation, decision, selected_tool, handoff_to, "completed", started, time.time())
        self.history.append(turn)
        self.trace.log(turn_id=turn_id, agent_name=agent, tool_name=selected_tool, phase=phase, status="completed", target_url=self.target, message=decision, evidence_summary=evidence_summary, progress_percent=progress_percent)
        return turn

    def route_tools(self, *, phase: str, scan_mode: str, available_inputs: set[str], limit: int = 10) -> list[dict[str, Any]]:
        return [tool.to_dict() for tool in self.router.select(phase=phase, scan_mode=scan_mode, available_inputs=available_inputs, limit=limit)]

    def summary(self) -> dict[str, Any]:
        return {"agents": self.registry.names(), "turns": [turn.to_dict() for turn in self.history], "tool_matrix": self.router.matrix()}
