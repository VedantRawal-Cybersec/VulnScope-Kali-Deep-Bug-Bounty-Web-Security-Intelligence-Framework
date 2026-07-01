#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

DIRECT_EVIDENCE_TYPES = {
    "cross-session/cross-account comparison",
    "server-side error signature",
    "redirect/fetch target confirmation",
    "header inspection",
}

HIGH_IMPACT = {"IDOR/BOLA", "SQLi", "SSRF", "Open Redirect", "CORS", "Auth/JWT"}
MEDIUM_IMPACT = {"CSRF", "Safe Parameter Review"}
LOW_IMPACT = {"Header Hardening"}


def _joined(item: dict[str, Any]) -> str:
    return " ".join(str(v) for v in item.values() if v not in (None, "", [], {})).lower()


def _clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 3)


def evidence_strength(item: dict[str, Any], evidence_type: str | None, evidence_detail: str) -> float:
    text = _joined(item) + " " + str(evidence_detail or "").lower()
    if not evidence_type:
        return 0.0
    if evidence_type in DIRECT_EVIDENCE_TYPES:
        score = 0.8
    elif evidence_type == "structural response diff":
        score = 0.6
    else:
        score = 0.4
    if any(x in text for x in ["actual diff", "request id", "response id", "captured", "access-control-allow", "location header", "callback", "stack trace"]):
        score += 0.15
    if any(x in text for x in ["keyword only", "parameter name", "hypothesis", "no baseline"]):
        score -= 0.25
    return _clamp(score)


def reproducibility(item: dict[str, Any], control_comparison_result: str) -> float:
    text = _joined(item) + " " + str(control_comparison_result or "").lower()
    score = 0.0
    if any(x in text for x in ["reproduced", "2 independent", "two requests", "second request", "twice"]):
        score += 0.55
    if any(x in text for x in ["control", "baseline", "known-safe", "known safe", "no anomaly"]):
        score += 0.35
    if any(x in text for x in ["normal variance", "unstable", "timeout", "not reproduced"]):
        score -= 0.25
    return _clamp(score)


def impact_estimate(vulnerability_type: str, item: dict[str, Any]) -> float:
    text = _joined(item)
    if vulnerability_type in HIGH_IMPACT:
        score = 0.7
    elif vulnerability_type in MEDIUM_IMPACT:
        score = 0.5
    elif vulnerability_type in LOW_IMPACT:
        score = 0.25
    else:
        score = 0.35
    if any(x in text for x in ["sensitive", "account", "user data", "private", "token", "authorization", "credential", "admin"]):
        score += 0.2
    if any(x in text for x in ["header", "best practice", "hardening", "informational"]):
        score -= 0.2
    return _clamp(score)


def confidence_tier(score: float, evidence_type: str | None, has_control_or_repro: bool) -> str:
    if not evidence_type:
        return "low"
    if score >= 0.75 and has_control_or_repro:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def decision(vulnerability_type: str, confidence: str, evidence_type: str | None, item: dict[str, Any]) -> tuple[str, str, str, str]:
    text = _joined(item)
    direct_evidence = evidence_type in DIRECT_EVIDENCE_TYPES or any(x in text for x in ["confirmed", "validated", "verified", "proven", "cross-account", "callback"])
    if confidence == "high" and direct_evidence:
        return (
            "CONFIRMED",
            "Confirmed by comparable evidence artifact and reproduced/control-backed confidence.",
            "Potentially reportable after final human review",
            "Lower risk because reproduced evidence and a control/baseline comparison are present; still requires final human review.",
        )
    if confidence in {"medium", "high"}:
        return (
            "REVIEW LEAD",
            "Behavioral evidence exists but the confirmation threshold is not fully met.",
            "Review lead only",
            "Could still be benign if the observed difference is expected application variance or lacks user-impact proof.",
        )
    return (
        "NOISE",
        "No behavioral evidence artifact met the confirmation threshold.",
        "Do not report",
        "Suppressed because it is ineligible, duplicate, or lacks captured comparable evidence.",
    )


def score_candidate(
    *,
    vulnerability_type: str,
    item: dict[str, Any],
    evidence_type: str | None,
    evidence_detail: str,
    control_comparison_result: str,
) -> dict[str, Any]:
    ev = evidence_strength(item, evidence_type, evidence_detail)
    repro = reproducibility(item, control_comparison_result)
    impact = impact_estimate(vulnerability_type, item)
    score = _clamp((ev * 0.4) + (repro * 0.3) + (impact * 0.3))
    has_control_or_repro = repro >= 0.35
    tier = confidence_tier(score, evidence_type, has_control_or_repro)
    cls, rationale, reportability, fp_notes = decision(vulnerability_type, tier, evidence_type, item)
    return {
        "confidence": tier,
        "confidence_score": score,
        "score_breakdown": {
            "evidence_strength": ev,
            "reproducibility": repro,
            "impact_estimate": impact,
            "formula": "evidence_strength*0.4 + reproducibility*0.3 + impact_estimate*0.3",
        },
        "classification": cls,
        "decision_rationale": rationale,
        "reportability": reportability,
        "false_positive_risk_notes": fp_notes,
    }
