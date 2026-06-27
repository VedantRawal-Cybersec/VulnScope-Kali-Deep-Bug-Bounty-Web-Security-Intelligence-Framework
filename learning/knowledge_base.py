from __future__ import annotations

ENDPOINT_RISK_KEYWORDS = {
    "admin": "Administrative area review",
    "internal": "Internal route exposure review",
    "debug": "Debug route exposure review",
    "api": "API security review",
    "graphql": "GraphQL surface review",
    "swagger": "OpenAPI/Swagger documentation review",
    "upload": "File upload security review",
    "download": "File access control review",
    "export": "Bulk export and sensitive data review",
    "invoice": "Object-level authorization review",
    "order": "Object-level authorization review",
    "payment": "Payment workflow review",
    "profile": "User object access review",
    "user": "User object access review",
    "search": "Input reflection and injection review",
    "redirect": "Redirect flow review",
    "callback": "Callback and redirect flow review",
}

PARAMETER_RISK_KEYWORDS = {
    "id": "Object reference review",
    "user_id": "User object authorization review",
    "account_id": "Account authorization review",
    "order_id": "Order ownership review",
    "invoice_id": "Invoice ownership review",
    "file": "File access review",
    "path": "Path handling review",
    "url": "Redirect / server-side fetch review",
    "redirect": "Redirect review",
    "next": "Auth-flow redirect review",
    "returnurl": "Auth-flow redirect review",
    "callback": "Callback review",
    "q": "Search reflection review",
    "search": "Search reflection review",
}

REMEDIATION_KNOWLEDGE = {
    "access_control": [
        "Enforce server-side authorization for every object access.",
        "Deny access when the authenticated user does not own or have permission for the object.",
        "Log unauthorized object access attempts for investigation.",
    ],
    "xss": [
        "Encode user-controlled output according to the rendering context.",
        "Apply a restrictive Content-Security-Policy where appropriate.",
        "Validate and normalize user input server-side.",
    ],
    "sqli": [
        "Use parameterized queries or prepared statements.",
        "Avoid string concatenation when building database queries.",
        "Return generic error messages instead of database error details.",
    ],
    "cors": [
        "Avoid reflecting arbitrary Origin values.",
        "Allow only trusted origins that require browser-based access.",
        "Do not combine wildcard origin policy with credentialed requests.",
    ],
    "exposure": [
        "Remove secrets and sensitive configuration from client-side assets.",
        "Restrict access to debug, backup, and internal files.",
        "Enforce server-side authorization for sensitive endpoints.",
    ],
}


def classify_endpoint_path(path: str) -> list[dict[str, str]]:
    lowered = path.lower()
    matches = []
    for keyword, category in ENDPOINT_RISK_KEYWORDS.items():
        if keyword in lowered:
            matches.append({"keyword": keyword, "category": category})
    return matches


def classify_parameter(name: str) -> str | None:
    return PARAMETER_RISK_KEYWORDS.get(name.lower())
