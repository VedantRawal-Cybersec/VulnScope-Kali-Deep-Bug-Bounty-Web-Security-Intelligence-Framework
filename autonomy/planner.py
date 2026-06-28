from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Any

SAFE_ACTIONS = [
    "scope_check",
    "passive_recon",
    "har_import_review",
    "agent_core_review",
    "model_council_review",
    "finding_quality",
    "report_v2",
]

CONTROLLED_ACTIONS = [
    "auto_mode_full",
    "authenticated_owned_account_review",
]


@dataclass
class PlannedStep:
    step_id: str
    action: str
    risk_level: str
    requires_approval: bool
    reason: str
    inputs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sid(action: str, target: str) -> str:
    return hashlib.sha1(f"{action}:{target}".encode()).hexdigest()[:12]


def build_autonomous_plan(target: str, mode: str = "bounty", har_path: str | None = None, max_controlled: bool = False) -> list[PlannedStep]:
    steps: list[PlannedStep] = []
    def add(action: str, risk: str, approval: bool, reason: str, extra: dict[str, Any] | None = None) -> None:
        steps.append(PlannedStep(_sid(action, target), action, risk, approval, reason, {"target": target, "mode": mode, **(extra or {})}))

    add("scope_check", "safe", False, "Confirm target is allowed by local scope policy")
    add("passive_recon", "safe", False, "Collect passive and low-risk surface evidence")
    if har_path:
        add("har_import_review", "safe", False, "Import user-provided browser/Burp traffic for offline review", {"har_path": har_path})
    add("agent_core_review", "safe", False, "Run deterministic specialist agents against collected evidence")
    add("model_council_review", "safe", False, "Ask configured AI providers for redacted evidence-first review")
    add("finding_quality", "safe", False, "Deduplicate and score candidates by evidence quality")
    add("report_v2", "safe", False, "Generate portfolio-ready executive and technical report")
    if max_controlled:
        add("auto_mode_full", "controlled", True, "Optional deeper tool orchestration requires approval and scope confirmation")
        if mode in {"pentest", "comprehensive"}:
            add("authenticated_owned_account_review", "controlled", True, "Only owned accounts; requires local credentials and explicit approval")
    return steps
