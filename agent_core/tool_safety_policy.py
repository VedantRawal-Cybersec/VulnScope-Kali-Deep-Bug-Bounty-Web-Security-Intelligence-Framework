from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ToolSafetyDecision:
    allowed: bool
    risk_level: str
    reason: str


BLOCKED_KEYWORDS = [
    "dump database",
    "credential capture",
    "steal cookie",
    "bypass mfa",
    "bypass captcha",
    "persistence",
    "reverse shell",
    "privilege escalation",
    "delete account",
    "wire transfer",
    "purchase",
]

APPROVAL_KEYWORDS = [
    "scan",
    "crawl",
    "probe",
    "authenticated",
    "subdomain",
    "request",
]


def assess_action(action: str) -> ToolSafetyDecision:
    low = action.lower()
    for keyword in BLOCKED_KEYWORDS:
        if keyword in low:
            return ToolSafetyDecision(False, "blocked", f"blocked sensitive action keyword: {keyword}")
    for keyword in APPROVAL_KEYWORDS:
        if keyword in low:
            return ToolSafetyDecision(True, "approval-required", f"approval required for action keyword: {keyword}")
    return ToolSafetyDecision(True, "review-only", "review-only action")


def allowed_tool_categories() -> dict[str, str]:
    return {
        "reconnaissance": "allowed when authorized; passive preferred",
        "web_validation": "allowed with non-destructive templates and rate limits",
        "authenticated_review": "allowed for owned accounts only",
        "reporting": "allowed",
        "learning_lab": "allowed in local labs/CTFs only",
        "sensitive_actions": "blocked by default",
    }
