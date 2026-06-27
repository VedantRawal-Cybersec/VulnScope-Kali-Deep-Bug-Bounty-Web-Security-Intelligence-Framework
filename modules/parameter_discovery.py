from __future__ import annotations

from urllib.parse import urlparse

from core.evidence_store import EvidenceStore, Finding

RISKY_PARAMETER_HINTS = {
    "id": "Object identifier; review for access-control or injection behavior.",
    "user": "User-related parameter; review authorization boundaries.",
    "user_id": "User object identifier; review IDOR/BOLA risk.",
    "account_id": "Account object identifier; review object-level authorization.",
    "order_id": "Order object identifier; review object ownership controls.",
    "file": "File/path related parameter; review file access controls.",
    "path": "Path-related parameter; review file/path handling.",
    "url": "URL parameter; review redirect/SSRF-style behavior manually.",
    "redirect": "Redirect parameter; review open redirect behavior.",
    "next": "Navigation parameter; review redirect/auth-flow behavior.",
    "returnurl": "Return URL parameter; review redirect/auth-flow behavior.",
    "q": "Search/input parameter; review reflection and injection behavior.",
    "search": "Search/input parameter; review reflection and injection behavior.",
}


def analyze_parameters(store: EvidenceStore) -> None:
    risky_hits: list[dict[str, str]] = []

    for endpoint, params in store.parameters.items():
        for param in params:
            normalized = param.lower()
            if normalized in RISKY_PARAMETER_HINTS:
                risky_hits.append(
                    {
                        "endpoint": endpoint,
                        "parameter": param,
                        "reason": RISKY_PARAMETER_HINTS[normalized],
                    }
                )

    store.metadata["parameters_identified"] = sum(len(v) for v in store.parameters.values())
    store.metadata["risky_parameter_hints"] = len(risky_hits)

    if risky_hits:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Risk-Relevant Parameters Identified",
                category="Parameter Intelligence",
                severity="Info",
                confidence="Medium",
                status="Manual Review Required",
                endpoint="Multiple endpoints",
                where_found="URL and form parameter discovery",
                how_detected=["Parameter names matched known security review patterns"],
                why_risky="Certain parameter names often indicate object references, redirects, search inputs, or file/path handling and should be manually validated in authorized scope.",
                evidence={"hits": risky_hits[:25]},
                recommended_validation=["Review listed parameters using safe manual testing inside the authorized scope."],
                remediation=["Apply server-side validation, authorization checks, and output encoding depending on parameter purpose."],
            )
        )
