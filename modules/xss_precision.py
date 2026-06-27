from __future__ import annotations

from html import unescape

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import ResponseRecord
from learning.knowledge_base import REMEDIATION_KNOWLEDGE

INPUT_HINTS = ("q", "query", "search", "keyword", "term", "name", "message", "comment")


def analyze_xss_precision(store: EvidenceStore, responses: list[ResponseRecord]) -> None:
    """Non-destructive XSS precision signals.

    This module does not inject payloads. It only identifies existing parameters
    and reflected query values already present in crawled URLs, then correlates
    them with weak browser protection signals such as missing CSP.
    """
    reflection_hits: list[dict[str, str]] = []

    for response in responses:
        if response.error or not response.text:
            continue
        params = store.parameters.get(response.url, [])
        if not params:
            continue
        body = unescape(response.text.lower())
        for param in params:
            if param.lower() in INPUT_HINTS and param.lower() in body:
                reflection_hits.append(
                    {
                        "endpoint": response.url,
                        "parameter": param,
                        "reflection_type": "parameter name observed in response body",
                    }
                )

    root_headers = store.metadata.get("root_probe", {})
    missing_csp = any(
        finding.title == "Missing Content-Security-Policy Header"
        for finding in store.findings
    )

    store.metadata["xss_precision"] = {
        "reflection_signal_count": len(reflection_hits),
        "reflection_hits": reflection_hits[:50],
        "missing_csp_signal": missing_csp,
    }

    if reflection_hits:
        confidence = "High" if missing_csp else "Medium"
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Potential Reflected Input Review Candidate",
                category="XSS Precision",
                severity="Medium",
                confidence=confidence,
                status="Manual Validation Required",
                endpoint="Multiple endpoints",
                where_found="Parameter and response reflection signal analysis",
                how_detected=[
                    "Input-like parameter names were found and related terms appeared in textual responses",
                    "No active XSS payloads were injected by this module",
                ],
                why_risky="User-controlled input that appears in browser-rendered responses may require output encoding review. This is a signal that requires safe manual validation.",
                evidence={
                    "reflection_hits": reflection_hits[:25],
                    "missing_csp_signal": missing_csp,
                },
                recommended_validation=[
                    "Manually review the exact reflection context in an authorized environment.",
                    "Confirm whether output encoding prevents script execution.",
                    "Do not test payloads outside allowed bug bounty scope.",
                ],
                remediation=REMEDIATION_KNOWLEDGE["xss"],
            )
        )
