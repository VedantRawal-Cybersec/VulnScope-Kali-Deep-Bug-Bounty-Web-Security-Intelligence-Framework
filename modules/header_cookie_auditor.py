from __future__ import annotations

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import ResponseRecord

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "why": "A missing CSP can increase the impact of client-side injection issues.",
        "remediation": "Define a restrictive Content-Security-Policy appropriate for the application.",
    },
    "Strict-Transport-Security": {
        "severity": "Low",
        "why": "A missing HSTS header may allow downgrade or insecure transport scenarios on HTTPS sites.",
        "remediation": "Add Strict-Transport-Security after confirming HTTPS is correctly configured.",
    },
    "X-Frame-Options": {
        "severity": "Low",
        "why": "Missing frame protection may increase clickjacking exposure.",
        "remediation": "Add X-Frame-Options or an equivalent CSP frame-ancestors directive.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "why": "Missing nosniff protection can allow MIME-type confusion in some browser contexts.",
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    "Referrer-Policy": {
        "severity": "Info",
        "why": "A missing referrer policy can leak unnecessary URL information across origins.",
        "remediation": "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    },
}


def audit_headers_and_cookies(store: EvidenceStore, response: ResponseRecord) -> None:
    headers_lower = {key.lower(): value for key, value in response.headers.items()}

    for header, details in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            store.add_finding(
                Finding(
                    finding_id=store.next_finding_id(),
                    title=f"Missing {header} Header",
                    category="Security Headers",
                    severity=details["severity"],
                    confidence="High",
                    status="Confirmed Observation",
                    endpoint=response.url,
                    where_found="Root HTTP response header audit",
                    how_detected=[f"{header} header was not present in the HTTP response"],
                    why_risky=details["why"],
                    evidence={"missing_header": header, "status_code": response.status_code},
                    recommended_validation=["Review whether this header is intentionally omitted for this application."],
                    remediation=[details["remediation"]],
                )
            )

    set_cookie_headers = response.headers.get("Set-Cookie", "")
    if set_cookie_headers:
        lowered = set_cookie_headers.lower()
        if "httponly" not in lowered:
            store.add_finding(
                Finding(
                    finding_id=store.next_finding_id(),
                    title="Cookie Missing HttpOnly Attribute",
                    category="Cookie Security",
                    severity="Medium",
                    confidence="Medium",
                    status="Potential",
                    endpoint=response.url,
                    where_found="Set-Cookie response header",
                    how_detected=["Set-Cookie header was observed without an HttpOnly attribute signal"],
                    why_risky="Cookies without HttpOnly may be accessible to client-side scripts if an XSS condition exists.",
                    evidence={"cookie_attribute": "HttpOnly", "present": False},
                    recommended_validation=["Check all session-related cookies manually in browser developer tools."],
                    remediation=["Set HttpOnly on sensitive cookies, especially session cookies."],
                )
            )
        if response.url.startswith("https://") and "secure" not in lowered:
            store.add_finding(
                Finding(
                    finding_id=store.next_finding_id(),
                    title="Cookie Missing Secure Attribute",
                    category="Cookie Security",
                    severity="Medium",
                    confidence="Medium",
                    status="Potential",
                    endpoint=response.url,
                    where_found="Set-Cookie response header",
                    how_detected=["Set-Cookie header was observed over HTTPS without a Secure attribute signal"],
                    why_risky="Sensitive cookies without Secure may be transmitted over insecure channels if the site is accessed over HTTP.",
                    evidence={"cookie_attribute": "Secure", "present": False},
                    recommended_validation=["Confirm whether the affected cookie is sensitive or session-related."],
                    remediation=["Set Secure on sensitive cookies served over HTTPS."],
                )
            )
