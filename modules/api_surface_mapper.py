from __future__ import annotations

from urllib.parse import urlparse

from core.evidence_store import EvidenceStore, Finding

API_HINTS = ("/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/json/", "/swagger", "/openapi")
OBJECT_HINTS = ("id", "user", "account", "order", "invoice", "profile", "payment")


def map_api_surface(store: EvidenceStore) -> None:
    api_routes: list[dict[str, object]] = []
    object_routes: list[dict[str, object]] = []

    for endpoint in sorted(store.endpoints):
        parsed = urlparse(endpoint)
        path = parsed.path.lower()
        is_api = any(hint in path for hint in API_HINTS)
        has_object_hint = any(hint in path for hint in OBJECT_HINTS)
        if is_api:
            api_routes.append({"endpoint": endpoint, "path": parsed.path})
        if is_api and has_object_hint:
            object_routes.append(
                {
                    "endpoint": endpoint,
                    "path": parsed.path,
                    "review_type": "Object-level authorization / API access review",
                }
            )

    store.metadata["api_surface_mapper"] = {
        "api_routes": api_routes[:200],
        "api_route_count": len(api_routes),
        "object_route_candidates": object_routes[:100],
        "object_route_candidate_count": len(object_routes),
    }

    if api_routes:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="API Surface Mapped",
                category="API Security Review",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint="Multiple API-like routes",
                where_found="Endpoint route mapping",
                how_detected=["Routes containing API, GraphQL, versioned API, Swagger, or OpenAPI indicators were discovered"],
                why_risky="This is not a vulnerability. API routes often require focused authentication, authorization, CORS, rate-limit, and sensitive-data review.",
                evidence={"api_route_count": len(api_routes), "api_routes_sample": api_routes[:30]},
                recommended_validation=["Review API routes for authentication, object authorization, CORS, and excessive data exposure."],
                remediation=["Apply server-side authorization and input validation to all API routes."],
            )
        )

    if object_routes:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Object-Oriented API Routes Identified",
                category="Access Control / IDOR Candidate",
                severity="Medium",
                confidence="Medium",
                status="Manual Validation Required",
                endpoint="Multiple API-like object routes",
                where_found="API route classification",
                how_detected=["API-like routes also contained user, order, account, invoice, profile, or payment indicators"],
                why_risky="Object-oriented API routes can be vulnerable if the server checks authentication but fails to enforce object ownership or authorization.",
                evidence={"object_route_candidates": object_routes[:30]},
                recommended_validation=["Validate object authorization using two authorized test accounts. Do not access data outside approved scope."],
                remediation=["Enforce object-level authorization checks on every object-specific API route."],
            )
        )
