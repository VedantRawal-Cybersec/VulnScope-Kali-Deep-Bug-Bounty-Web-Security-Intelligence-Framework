#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

CONFIRMED_ALLOWED = {"Reflection", "Input Handling", "Redirect Review", "Availability"}
INFORMATIONAL_CATEGORIES = {"Security Headers", "Cookies", "Metadata", "CSP", "TLS"}


@dataclass
class ValidationResult:
    accepted: bool
    status: str
    severity: str
    confidence: int
    reason: str
    evidence_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceValidator:
    """Deterministic anti-false-positive validation.

    Rules:
    - no evidence means no confirmed finding
    - header/cookie hardening is informational
    - reflection is confirmed reflection, not XSS
    - classification-only findings remain potential or informational
    """

    def validate(self, finding: dict[str, Any]) -> ValidationResult:
        title = str(finding.get("title") or "")
        category = str(finding.get("category") or "")
        evidence = str(finding.get("evidence") or "").strip()
        status = str(finding.get("status") or "Potential")
        severity = str(finding.get("severity") or "INFO").upper()
        confidence = int(finding.get("confidence") or 0)

        if category in INFORMATIONAL_CATEGORIES or title.lower().startswith(("missing ", "cookie missing", "robots.txt", "security.txt")):
            return ValidationResult(True, "Informational", "INFO", min(max(confidence, 60), 95), "passive hardening/metadata observation")

        if not evidence:
            return ValidationResult(True, "Potential", "INFO", min(confidence, 40), "evidence was blank; downgraded")

        if "xss" in title.lower() and "reflection" in evidence.lower():
            return ValidationResult(True, "Potential", "LOW", min(confidence, 70), "reflection is not automatically XSS")

        if status.lower() == "confirmed":
            if category in CONFIRMED_ALLOWED or re.search(r"exact .*canary|harmless.*canary|baseline http|http \d{3}", evidence, re.I):
                return ValidationResult(True, "Confirmed", severity, max(confidence, 80), "direct evidence present")
            return ValidationResult(True, "Potential", severity if severity != "CRITICAL" else "MEDIUM", min(confidence, 70), "confirmed label lacked strong evidence pattern")

        normalized = "Informational" if status.lower().startswith("info") else "Potential"
        return ValidationResult(True, normalized, severity, max(0, min(100, confidence)), "non-confirmed finding retained")

    def normalize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        result = self.validate(finding)
        finding["status"] = result.status
        finding["severity"] = result.severity
        finding["confidence"] = result.confidence
        finding["validation_reason"] = result.reason
        finding["evidence_validated"] = result.accepted
        return finding

    def validate_report_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        findings = payload.get("findings") or []
        confirmed: list[dict[str, Any]] = []
        potential: list[dict[str, Any]] = []
        informational: list[dict[str, Any]] = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            normalized = self.normalize_finding(dict(item))
            status = normalized.get("status")
            if status == "Confirmed":
                confirmed.append(normalized)
            elif status == "Informational":
                informational.append(normalized)
            else:
                potential.append(normalized)
        payload["confirmed_vulnerabilities"] = confirmed
        payload["potential_review_leads"] = potential
        payload["informational_observations"] = informational
        return payload
