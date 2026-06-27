from __future__ import annotations

import re

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import ResponseRecord
from learning.knowledge_base import REMEDIATION_KNOWLEDGE

SENSITIVE_KEYWORDS = [
    "api_key",
    "apikey",
    "secret",
    "token",
    "authorization",
    "bearer",
    "password",
    "private_key",
    "aws_access_key",
    "firebase",
    "supabase",
    "sentry_dsn",
]

PUBLIC_EXPOSURE_HINTS = [
    ".env",
    "backup",
    "debug",
    "config",
    "admin",
    "internal",
    "swagger",
    "openapi",
]


def find_sensitive_exposure_signals(store: EvidenceStore, responses: list[ResponseRecord]) -> None:
    keyword_hits: list[dict[str, str]] = []
    exposure_routes: list[str] = []

    for endpoint in sorted(store.endpoints):
        lowered = endpoint.lower()
        if any(hint in lowered for hint in PUBLIC_EXPOSURE_HINTS):
            exposure_routes.append(endpoint)

    for response in responses:
        if response.error or not response.text:
            continue
        text = response.text.lower()
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in text:
                keyword_hits.append(
                    {
                        "url": response.url,
                        "keyword_class": keyword,
                        "note": "Value redacted by design. Manual authorized review required.",
                    }
                )

    store.metadata["exposure_finder"] = {
        "keyword_hit_count": len(keyword_hits),
        "exposure_route_count": len(exposure_routes),
        "keyword_hits_sample": keyword_hits[:50],
        "exposure_routes_sample": exposure_routes[:50],
    }

    if keyword_hits:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Sensitive Keyword Signals Observed",
                category="Sensitive Exposure Review",
                severity="Medium",
                confidence="Medium",
                status="Manual Validation Required",
                endpoint="Multiple responses",
                where_found="Textual response keyword scan",
                how_detected=["Security-relevant keyword classes were observed in textual responses"],
                why_risky="This is a signal, not proof of secret exposure. Client-side or public responses containing secret-like keywords should be manually reviewed without publishing sensitive values.",
                evidence={"keyword_hits_sample": keyword_hits[:25]},
                recommended_validation=["Manually verify whether any sensitive values are exposed. Redact all values in reports."],
                remediation=REMEDIATION_KNOWLEDGE["exposure"],
            )
        )

    if exposure_routes:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Exposure-Prone Routes Identified",
                category="Sensitive Exposure Review",
                severity="Info",
                confidence="Medium",
                status="Manual Review Required",
                endpoint="Multiple endpoints",
                where_found="Endpoint path classification",
                how_detected=["Discovered endpoints matched backup, config, debug, admin, swagger, or OpenAPI-style exposure hints"],
                why_risky="This is a prioritization signal. These routes may be legitimate, but they should be reviewed for authentication and sensitive-data exposure.",
                evidence={"exposure_routes_sample": exposure_routes[:30]},
                recommended_validation=["Review exposure-prone routes only within authorized scope."],
                remediation=REMEDIATION_KNOWLEDGE["exposure"],
            )
        )
