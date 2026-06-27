from __future__ import annotations

from urllib.parse import urlparse

from core.evidence_store import EvidenceStore, Finding
from learning.knowledge_base import classify_endpoint_path


def analyze_deep_routes(store: EvidenceStore) -> None:
    route_hints: list[dict[str, object]] = []

    for endpoint in sorted(store.endpoints):
        path = urlparse(endpoint).path or "/"
        matches = classify_endpoint_path(path)
        if matches:
            route_hints.append(
                {
                    "endpoint": endpoint,
                    "path": path,
                    "matches": matches,
                }
            )

    store.metadata["deep_route_intelligence"] = {
        "classified_routes": len(route_hints),
        "route_hints": route_hints[:100],
    }

    if route_hints:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Risk-Relevant Routes Classified",
                category="DeepRoute Intelligence",
                severity="Info",
                confidence="Medium",
                status="Manual Review Required",
                endpoint="Multiple endpoints",
                where_found="Endpoint path classification",
                how_detected=["Discovered endpoint paths matched security review keywords from the knowledge base"],
                why_risky="This is a prioritization signal. Routes containing API, admin, user, order, upload, debug, or payment-related terms often deserve focused manual review.",
                evidence={"route_hints": route_hints[:25]},
                recommended_validation=["Manually review high-priority routes inside the authorized scope."],
                remediation=["Apply authentication, authorization, validation, and logging according to route purpose."],
            )
        )
