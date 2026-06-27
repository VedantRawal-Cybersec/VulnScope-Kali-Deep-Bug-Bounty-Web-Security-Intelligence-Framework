from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import RequestEngine, ResponseRecord
from core.scope_guard import is_same_domain

ENDPOINT_PATTERN = re.compile(r"['\"]((?:/|https?://)[A-Za-z0-9_./?&=%:#\-]+)['\"]")
RISK_KEYWORDS = [
    "admin",
    "internal",
    "debug",
    "upload",
    "api",
    "token",
    "auth",
    "user",
    "order",
    "payment",
    "invoice",
    "graphql",
    "swagger",
]


def mine_javascript_endpoints(
    responses: list[ResponseRecord],
    target_host: str,
    request_engine: RequestEngine,
    store: EvidenceStore,
) -> None:
    js_urls = sorted({url for url in store.endpoints if urlparse(url).path.lower().endswith(".js")})
    store.metadata["javascript_files_discovered"] = len(js_urls)

    discovered_from_js: set[str] = set()
    sensitive_keyword_hits: list[dict[str, str]] = []

    for js_url in js_urls[:25]:
        js_response = request_engine.get(js_url)
        if js_response.error or not js_response.text:
            continue

        for match in ENDPOINT_PATTERN.findall(js_response.text):
            endpoint = urljoin(js_response.url, match)
            if is_same_domain(endpoint, target_host):
                store.add_endpoint(endpoint)
                discovered_from_js.add(endpoint)

        lowered = js_response.text.lower()
        for keyword in RISK_KEYWORDS:
            if keyword in lowered:
                sensitive_keyword_hits.append({"file": js_url, "keyword_class": keyword})

    store.metadata["javascript_endpoints_discovered"] = len(discovered_from_js)

    if discovered_from_js:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Client-Side JavaScript Endpoints Discovered",
                category="Attack Surface Discovery",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint="Multiple JavaScript-derived endpoints",
                where_found="JavaScript endpoint mining",
                how_detected=["Same-domain routes were extracted from JavaScript file content"],
                why_risky="Client-side JavaScript may reveal API routes or application areas that are not directly linked from normal navigation.",
                evidence={
                    "endpoint_count": len(discovered_from_js),
                    "sample_endpoints": sorted(discovered_from_js)[:10],
                },
                recommended_validation=["Review discovered endpoints for authentication, authorization, and sensitive data exposure."],
                remediation=["Do not rely on hidden client-side routes for security. Enforce server-side access control."],
            )
        )

    if sensitive_keyword_hits:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Security-Relevant Keywords Observed in JavaScript",
                category="Sensitive Exposure Review",
                severity="Info",
                confidence="Medium",
                status="Manual Review Required",
                endpoint="Client-side JavaScript files",
                where_found="JavaScript keyword scan",
                how_detected=["Security-relevant keywords were observed in client-side JavaScript"],
                why_risky="Security-related keywords in client-side code can point to sensitive workflows, APIs, or configuration areas that need manual review.",
                evidence={"keyword_hits_sample": sensitive_keyword_hits[:20]},
                recommended_validation=["Manually inspect the related JavaScript file in an authorized environment. Do not publish secrets or sensitive values."],
                remediation=["Avoid embedding sensitive secrets in client-side JavaScript and enforce server-side authorization."],
            )
        )
