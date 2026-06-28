from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GateDecision:
    allowed: bool
    reason: str


def require_confirmation(message: str, auto_yes: bool = False) -> GateDecision:
    if auto_yes:
        return GateDecision(True, "auto-confirmed by user flag")
    print("\n┌──────────────────── Human Approval Gate ────────────────────┐")
    print(message)
    print("└──────────────────────────────────────────────────────────────┘")
    answer = input("Approve? yes/no: ").strip().lower()
    if answer in {"yes", "y"}:
        return GateDecision(True, "approved by user")
    return GateDecision(False, "not approved")


def classify_risk(action: str) -> str:
    low = action.lower()
    if any(word in low for word in ["delete", "purchase", "payment", "change password", "remove", "submit order"]):
        return "blocked-sensitive"
    if any(word in low for word in ["crawl", "request", "probe", "scan"]):
        return "approval-required"
    return "review-only"
