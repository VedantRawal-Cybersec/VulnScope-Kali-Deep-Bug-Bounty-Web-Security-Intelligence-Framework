from __future__ import annotations

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import ResponseRecord
from learning.knowledge_base import REMEDIATION_KNOWLEDGE


def analyze_cors(store: EvidenceStore, response: ResponseRecord) -> None:
    headers = {key.lower(): value for key, value in response.headers.items()}
    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials")

    store.metadata["cors_analysis"] = {
        "access_control_allow_origin": allow_origin,
        "access_control_allow_credentials": allow_credentials,
    }

    if allow_origin == "*" and str(allow_credentials).lower() == "true":
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Potentially Unsafe CORS Header Combination",
                category="CORS Security",
                severity="High",
                confidence="High",
                status="Confirmed Observation",
                endpoint=response.url,
                where_found="Root HTTP response headers",
                how_detected=["Access-Control-Allow-Origin was wildcard and credentials appeared enabled"],
                why_risky="Wildcard origins should not be combined with credentialed browser requests because it can expose sensitive responses to unintended origins.",
                evidence={
                    "access_control_allow_origin": allow_origin,
                    "access_control_allow_credentials": allow_credentials,
                },
                recommended_validation=["Confirm whether sensitive authenticated responses are reachable with these CORS headers."],
                remediation=REMEDIATION_KNOWLEDGE["cors"],
            )
        )
    elif allow_origin:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="CORS Policy Observed",
                category="CORS Security",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint=response.url,
                where_found="Root HTTP response headers",
                how_detected=["CORS response headers were present"],
                why_risky="This is not necessarily a vulnerability. CORS policy should be reviewed for overly broad origins, credentialed requests, and sensitive APIs.",
                evidence={
                    "access_control_allow_origin": allow_origin,
                    "access_control_allow_credentials": allow_credentials,
                },
                recommended_validation=["Review whether the allowed origin policy is intentionally configured and limited to trusted origins."],
                remediation=REMEDIATION_KNOWLEDGE["cors"],
            )
        )
