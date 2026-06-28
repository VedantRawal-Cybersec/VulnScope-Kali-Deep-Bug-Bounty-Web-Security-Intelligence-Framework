from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from review_agents.specialists import SPECIALIST_AGENTS


@dataclass
class AgentSpec:
    name: str
    purpose: str
    risk_level: str
    enabled: bool = True


def list_agent_specs() -> list[AgentSpec]:
    return [
        AgentSpec("ReconReviewAgent", "Summarize passive surface and archived URL coverage", "review-only"),
        AgentSpec("AppProfileAgent", "Infer application profile and recommended review path", "review-only"),
        AgentSpec("APIReviewAgent", "Identify API and GraphQL review candidates", "review-only"),
        AgentSpec("AuthReviewAgent", "Identify authentication and session flow review candidates", "review-only"),
        AgentSpec("IDORBOLAReviewAgent", "Identify object-bound routes that need owned two-account validation", "review-only"),
        AgentSpec("JSIntelReviewAgent", "Identify JavaScript and source-map review candidates", "review-only"),
        AgentSpec("ValidationReviewAgent", "Convert observations into validation tasks", "review-only"),
    ]


def get_review_agents():
    return SPECIALIST_AGENTS


def registry_markdown() -> str:
    lines = ["# VulnScope Agent Registry", ""]
    for spec in list_agent_specs():
        status = "enabled" if spec.enabled else "disabled"
        lines.append(f"- **{spec.name}** ({status}, {spec.risk_level}) — {spec.purpose}")
    return "\n".join(lines)
