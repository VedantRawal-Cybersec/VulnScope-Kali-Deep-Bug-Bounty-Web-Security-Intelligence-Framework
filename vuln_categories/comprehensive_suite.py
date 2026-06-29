from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

OUT_DIR = Path("reports/output/comprehensive-suite")
INPUTS = [
    "reports/output/evidence.json",
    "reports/output/recon/domain-expansion.json",
    "reports/output/imports/har-import.json",
    "reports/output/safe-discovery/safe-discovery.json",
    "reports/output/category-suite/category-suite.json",
    "reports/output/auth/account-comparison.json",
    "reports/output/auth/auth-crawl-account_a.json",
    "reports/output/auth/auth-crawl-account_b.json",
    "reports/output/arsenal/katana-urls.txt",
    "reports/output/arsenal/gau-urls.txt",
    "reports/output/arsenal/waybackurls.txt",
    "reports/output/arsenal/arjun.txt",
    "reports/output/arsenal/httpx.txt",
    "reports/output/arsenal/nuclei-safe.txt",
]

CATEGORIES: dict[str, list[dict[str, Any]]] = {
    "xss": [
        {"name": "reflection_parameters", "where": "param", "tokens": ["q", "query", "search", "keyword", "term", "message", "comment"], "title": "XSS reflection-prone parameter surface"},
        {"name": "dom_sinks", "where": "text", "tokens": ["innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "location.hash", "location.search"], "title": "DOM sink pattern requires client-side review"},
        {"name": "callback_context", "where": "param", "tokens": ["callback", "jsonp", "cb"], "title": "Callback parameter requires script-context review"},
        {"name": "stored_content_routes", "where": "path", "tokens": ["comment", "review", "message", "profile", "feedback", "wysiwyg"], "title": "User-content route requires stored-XSS review"},
        {"name": "js_assets", "where": "path", "tokens": [".js"], "title": "JavaScript asset queued for endpoint and sink review"},
        {"name": "missing_csp_context", "where": "text", "tokens": ["Missing Content-Security-Policy"], "title": "Missing CSP increases XSS impact if a sink is confirmed"},
    ],
    "idor_bola": [
        {"name": "object_id_params", "where": "param", "tokens": ["id", "uid", "uuid", "user", "account", "order", "invoice"], "title": "Object identifier parameter requires authorization review"},
        {"name": "tenant_routes", "where": "path", "tokens": ["tenant", "workspace", "organization", "org", "team", "company"], "title": "Tenant/workspace route requires isolation review"},
        {"name": "file_routes", "where": "path", "tokens": ["file", "download", "document", "invoice", "receipt", "export"], "title": "File or document route requires object access review"},
        {"name": "state_routes", "where": "path", "tokens": ["update", "edit", "delete", "remove", "create", "transfer"], "title": "State-changing route requires role and object authorization review"},
        {"name": "account_comparison", "where": "file", "tokens": ["reports/output/auth/account-comparison.json"], "title": "Account A/B comparison contains authorization review items"},
        {"name": "numeric_id_cluster", "where": "numeric_param", "tokens": ["id", "user", "account", "order"], "title": "Repeated numeric identifier pattern requires IDOR review"},
    ],
    "sqli": [
        {"name": "query_params", "where": "param", "tokens": ["q", "query", "search", "filter", "sort", "where"], "title": "Database-like query parameter requires SQLi review"},
        {"name": "numeric_lookup", "where": "param", "tokens": ["id", "item", "product", "order"], "title": "Numeric lookup parameter requires input-handling review"},
        {"name": "report_export", "where": "path", "tokens": ["report", "export", "csv", "download"], "title": "Reporting/export endpoint requires query safety review"},
        {"name": "search_routes", "where": "path", "tokens": ["search", "filter", "lookup", "find"], "title": "Search route requires backend query review"},
        {"name": "graphql_queries", "where": "path", "tokens": ["graphql", "gql"], "title": "GraphQL query endpoint requires resolver input review"},
        {"name": "db_error_text", "where": "text", "tokens": ["sql syntax", "mysql", "postgres", "sqlite", "odbc", "jdbc"], "title": "Database error text observed in collected evidence"},
    ],
    "ssrf": [
        {"name": "url_params", "where": "param", "tokens": ["url", "uri", "target", "endpoint", "callback", "webhook"], "title": "URL-taking parameter requires SSRF review"},
        {"name": "fetch_routes", "where": "path", "tokens": ["fetch", "proxy", "preview", "import", "webhook", "callback"], "title": "Server-side fetch route requires SSRF review"},
        {"name": "image_import", "where": "path", "tokens": ["avatar", "image", "media", "upload-from-url", "thumbnail"], "title": "Remote media import route requires SSRF review"},
        {"name": "pdf_render", "where": "path", "tokens": ["pdf", "render", "screenshot", "html2pdf"], "title": "Renderer endpoint requires network egress review"},
        {"name": "cloud_metadata_words", "where": "text", "tokens": ["metadata", "169.254", "aws", "gcp", "azure"], "title": "Cloud metadata language observed in evidence"},
        {"name": "integration_routes", "where": "path", "tokens": ["integration", "connect", "oauth", "api/import"], "title": "Integration route requires outbound request policy review"},
    ],
    "open_redirect": [
        {"name": "redirect_params", "where": "param", "tokens": ["redirect", "return", "return_to", "next", "continue", "destination"], "title": "Redirect parameter requires allowlist review"},
        {"name": "login_return", "where": "path", "tokens": ["login", "oauth", "sso", "callback"], "title": "Login/OAuth route requires return-url review"},
        {"name": "logout_return", "where": "path", "tokens": ["logout", "signout"], "title": "Logout route requires redirect validation review"},
        {"name": "external_link", "where": "path", "tokens": ["out", "external", "link", "go"], "title": "External-link route requires destination validation review"},
        {"name": "deep_link", "where": "param", "tokens": ["deeplink", "app", "continue_uri"], "title": "Deep-link parameter requires redirect policy review"},
        {"name": "oauth_state", "where": "param", "tokens": ["state", "client_id", "redirect_uri"], "title": "OAuth redirect parameters require exact-match validation review"},
    ],
    "cors": [
        {"name": "cors_headers", "where": "text", "tokens": ["access-control-allow-origin", "access-control-allow-credentials"], "title": "CORS headers require origin/credential review"},
        {"name": "api_routes", "where": "path", "tokens": ["api", "v1", "v2", "graphql"], "title": "API route requires CORS policy review"},
        {"name": "auth_api", "where": "path", "tokens": ["me", "account", "profile", "session"], "title": "Authenticated API route requires credentialed CORS review"},
        {"name": "upload_cors", "where": "path", "tokens": ["upload", "media", "file"], "title": "Upload route requires CORS and content policy review"},
        {"name": "subdomain_api", "where": "host", "tokens": ["api.", "cdn.", "static."], "title": "Subdomain surface requires cross-origin trust review"},
        {"name": "cors_candidate", "where": "text", "tokens": ["CORS reflects", "CORS wildcard"], "title": "Safe discovery flagged CORS review candidate"},
    ],
    "graphql": [
        {"name": "graphql_path", "where": "path", "tokens": ["graphql", "gql", "graphiql"], "title": "GraphQL endpoint requires schema and resolver review"},
        {"name": "introspection_words", "where": "text", "tokens": ["__schema", "__typename", "IntrospectionQuery"], "title": "GraphQL introspection indicators observed"},
        {"name": "resolver_ids", "where": "param", "tokens": ["id", "node", "cursor", "after", "before"], "title": "GraphQL-style identifier/pagination input requires BOLA review"},
        {"name": "mutation_words", "where": "text", "tokens": ["mutation", "create", "update", "delete"], "title": "GraphQL mutation wording requires authorization review"},
        {"name": "batching_words", "where": "text", "tokens": ["batch", "operationName", "variables"], "title": "GraphQL operation batching requires rate/authorization review"},
        {"name": "apollo_words", "where": "text", "tokens": ["Apollo", "urql", "relay"], "title": "GraphQL client framework detected for route extraction review"},
    ],
    "jwt_auth": [
        {"name": "jwt_words", "where": "text", "tokens": ["jwt", "bearer", "authorization"], "title": "Token-based auth indicators require JWT/session review"},
        {"name": "oauth_routes", "where": "path", "tokens": ["oauth", "oidc", "sso", "callback", "authorize"], "title": "OAuth/OIDC route requires auth-flow review"},
        {"name": "session_routes", "where": "path", "tokens": ["session", "login", "logout", "me", "profile"], "title": "Session route requires cookie and access review"},
        {"name": "role_words", "where": "text", "tokens": ["admin", "role", "permission", "scope"], "title": "Role/scope wording requires authorization matrix review"},
        {"name": "google_state", "where": "file", "tokens": ["reports/output/auth/states"], "title": "Google-authenticated session artifacts available for bounded review"},
        {"name": "cookie_findings", "where": "text", "tokens": ["Cookie missing", "SameSite", "HttpOnly", "Secure flag"], "title": "Cookie posture finding requires session-hardening review"},
    ],
    "lfi_rfi_path": [
        {"name": "file_params", "where": "param", "tokens": ["file", "path", "template", "page", "include", "download"], "title": "File/path parameter requires path traversal review"},
        {"name": "download_routes", "where": "path", "tokens": ["download", "file", "attachment", "export"], "title": "Download route requires path and object access review"},
        {"name": "template_routes", "where": "path", "tokens": ["template", "theme", "view", "page"], "title": "Template route requires safe include/render review"},
        {"name": "backup_words", "where": "path", "tokens": ["backup", "old", "archive", "dump"], "title": "Backup/archive route requires exposure review"},
        {"name": "config_words", "where": "path", "tokens": ["config", "env", "settings"], "title": "Config route requires sensitive file exposure review"},
        {"name": "file_error_words", "where": "text", "tokens": ["no such file", "permission denied", "open_basedir", "path traversal"], "title": "File-system error text observed in evidence"},
    ],
    "ssti_template": [
        {"name": "template_params", "where": "param", "tokens": ["template", "view", "theme", "format", "layout"], "title": "Template parameter requires SSTI/render review"},
        {"name": "render_routes", "where": "path", "tokens": ["render", "preview", "template", "email", "pdf"], "title": "Rendering route requires template safety review"},
        {"name": "engine_words", "where": "text", "tokens": ["jinja", "twig", "freemarker", "velocity", "handlebars", "mustache"], "title": "Template engine indicator observed"},
        {"name": "email_templates", "where": "path", "tokens": ["email", "notification", "message-template"], "title": "Email template route requires rendering-context review"},
        {"name": "cms_templates", "where": "path", "tokens": ["cms", "theme", "layout", "block"], "title": "CMS/template route requires input boundary review"},
        {"name": "server_error_words", "where": "text", "tokens": ["template error", "render error", "undefined variable"], "title": "Template error text observed in evidence"},
    ],
    "csrf": [
        {"name": "state_routes", "where": "path", "tokens": ["update", "delete", "create", "edit", "save", "transfer"], "title": "State-changing route requires CSRF control review"},
        {"name": "account_routes", "where": "path", "tokens": ["password", "email", "profile", "settings"], "title": "Account settings route requires CSRF review"},
        {"name": "cookie_samesite", "where": "text", "tokens": ["SameSite"], "title": "SameSite cookie posture requires CSRF context review"},
        {"name": "forms_text", "where": "text", "tokens": ["<form", "csrf", "xsrf"], "title": "Form/CSRF token indicators require manual review"},
        {"name": "admin_routes", "where": "path", "tokens": ["admin", "manage", "settings"], "title": "Admin route requires CSRF and role review"},
        {"name": "api_mutations", "where": "path", "tokens": ["api/update", "api/delete", "api/create"], "title": "API mutation route requires browser credential review"},
    ],
    "file_upload": [
        {"name": "upload_routes", "where": "path", "tokens": ["upload", "media", "avatar", "attachment"], "title": "Upload route requires content validation review"},
        {"name": "import_routes", "where": "path", "tokens": ["import", "csv", "excel", "xml"], "title": "Import route requires parser safety review"},
        {"name": "image_routes", "where": "path", "tokens": ["image", "photo", "thumbnail", "resize"], "title": "Image-processing route requires file validation review"},
        {"name": "storage_words", "where": "text", "tokens": ["s3", "bucket", "storage", "blob"], "title": "Cloud storage indicator requires upload/access review"},
        {"name": "public_file_paths", "where": "path", "tokens": ["uploads", "public", "static"], "title": "Public file path requires direct access review"},
        {"name": "metadata_words", "where": "text", "tokens": ["content-type", "mime", "filename"], "title": "File metadata handling requires review"},
    ],
    "secrets_exposure": [
        {"name": "env_candidate", "where": "text", "tokens": [".env", "Potential public .env"], "title": "Environment file exposure candidate requires urgent review"},
        {"name": "key_words", "where": "text", "tokens": ["api_key", "secret", "token", "private_key", "client_secret"], "title": "Secret-like text observed in collected evidence"},
        {"name": "source_maps", "where": "path", "tokens": [".map", "sourceMap", "webpack"], "title": "Source-map asset requires exposure review"},
        {"name": "git_exposure", "where": "text", "tokens": ["Public .git", ".git/HEAD"], "title": "Git metadata exposure candidate requires review"},
        {"name": "debug_routes", "where": "path", "tokens": ["debug", "trace", "actuator", "health", "metrics"], "title": "Debug/diagnostic route requires exposure review"},
        {"name": "backup_files", "where": "path", "tokens": ["backup", ".bak", ".old", ".zip", ".tar"], "title": "Backup artifact route requires exposure review"},
    ],
    "rate_limit_logic": [
        {"name": "login_routes", "where": "path", "tokens": ["login", "signin", "otp", "verify"], "title": "Login/verification route requires rate-limit review"},
        {"name": "password_routes", "where": "path", "tokens": ["password", "reset", "forgot"], "title": "Password-reset route requires abuse-control review"},
        {"name": "coupon_payment", "where": "path", "tokens": ["coupon", "discount", "payment", "checkout", "wallet"], "title": "Commerce route requires business-logic review"},
        {"name": "invite_routes", "where": "path", "tokens": ["invite", "referral", "share"], "title": "Invite/referral route requires anti-abuse review"},
        {"name": "search_rate", "where": "path", "tokens": ["search", "export", "download"], "title": "Bulk/search route requires throttling review"},
        {"name": "admin_logic", "where": "path", "tokens": ["admin", "approve", "reject", "role"], "title": "Admin workflow requires business-rule review"},
    ],
}

@dataclass
class Candidate:
    title: str
    category: str
    detector: str
    url: str
    evidence: list[str]
    severity: str = "info"
    confidence: float = 0.50
    source: str = "comprehensive_suite"
    validation_status: str = "review_candidate"
    exploit_status: str = "not_executed"
    remediation: str = "Validate manually on owned or explicitly authorized assets and enforce server-side controls."
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class ComprehensiveCategorySuite:
    """Broad, safe category review. This suite creates review candidates only.

    It does not inject payloads, brute-force identifiers, collect credentials,
    alter server state, or confirm impact. It converts existing recon/HAR/auth
    evidence into prioritized manual-validation tasks.
    """
    def __init__(self, target: str | None = None) -> None:
        self.target = target or "authorized-target"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.inputs = self._load_inputs()
        self.urls = sorted(self._extract_urls(self.inputs))
        self.text = json.dumps(self.inputs, ensure_ascii=False, default=str)[:2_000_000]

    def run(self) -> dict[str, Any]:
        started = time.time()
        candidates: list[Candidate] = []
        coverage: list[dict[str, Any]] = []
        for category, detectors in CATEGORIES.items():
            for detector in detectors:
                found = self._run_detector(category, detector)
                candidates.extend(found)
                coverage.append({"category": category, "detector": detector["name"], "candidates": len(found), "status": "ok"})
        deduped = self._dedupe(candidates)
        payload = {
            "target": self.target,
            "mode": "comprehensive_safe_review",
            "started_at": started,
            "ended_at": time.time(),
            "rules": {"payload_injection": False, "identifier_bruteforce": False, "credential_collection": False, "state_change": False, "impact_confirmation": False},
            "categories": sorted(CATEGORIES.keys()),
            "detectors_per_category": {k: len(v) for k, v in CATEGORIES.items()},
            "coverage": coverage,
            "candidates": [c.to_dict() for c in deduped],
            "summary": {"categories": len(CATEGORIES), "detectors": sum(len(v) for v in CATEGORIES.values()), "input_urls": len(self.urls), "candidates": len(deduped)},
        }
        (OUT_DIR / "comprehensive-suite.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUT_DIR / "comprehensive-suite.md").write_text(self._markdown(payload), encoding="utf-8")
        return payload

    def _load_inputs(self) -> dict[str, Any]:
        loaded: dict[str, Any] = {}
        for raw in INPUTS:
            p = Path(raw)
            if not p.exists():
                continue
            try:
                loaded[raw] = json.loads(p.read_text(encoding="utf-8", errors="ignore")) if p.suffix == ".json" else p.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                loaded[raw] = {"error": str(exc)}
        return loaded

    def _extract_urls(self, value: Any) -> set[str]:
        urls: set[str] = set()
        if isinstance(value, str):
            for match in re.findall(r"https?://[^\s'\"<>]+", value):
                urls.add(match.rstrip(").,;]"))
            for line in value.splitlines():
                line = line.strip()
                if line.startswith(("http://", "https://")):
                    urls.add(line)
        elif isinstance(value, list):
            for item in value:
                urls.update(self._extract_urls(item))
        elif isinstance(value, dict):
            for key in ["url", "endpoint", "request_url"]:
                val = value.get(key)
                if isinstance(val, str) and val.startswith(("http://", "https://")):
                    urls.add(val)
            for item in value.values():
                urls.update(self._extract_urls(item))
        return urls

    def _run_detector(self, category: str, detector: dict[str, Any]) -> list[Candidate]:
        where = detector["where"]
        tokens = [str(t).lower() for t in detector["tokens"]]
        out: list[Candidate] = []
        if where in {"text", "file"}:
            hay = self.text.lower()
            if any(t.lower() in hay for t in tokens):
                out.append(self._candidate(category, detector, self.target, [where]))
        elif where == "path":
            for url in self.urls:
                path = urlparse(url).path.lower()
                if any(t in path for t in tokens):
                    out.append(self._candidate(category, detector, url, ["path_token"]))
        elif where == "host":
            for url in self.urls:
                host = urlparse(url).netloc.lower()
                if any(t in host for t in tokens):
                    out.append(self._candidate(category, detector, url, ["host_token"]))
        elif where == "param":
            for url in self.urls:
                params = [p.lower() for p, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
                if any(any(t == p or t in p for t in tokens) for p in params):
                    out.append(self._candidate(category, detector, url, ["query_parameter_name"]))
        elif where == "numeric_param":
            counts: dict[str, tuple[int, str]] = {}
            for url in self.urls:
                for p, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
                    if v.isdigit() and len(v) >= 2 and any(t == p.lower() or t in p.lower() for t in tokens):
                        c, _ = counts.get(p, (0, url))
                        counts[p] = (c + 1, url)
            for p, (count, url) in counts.items():
                if count >= 2:
                    out.append(self._candidate(category, detector, url, [f"numeric_param:{p}"]))
        return out[:60]

    def _candidate(self, category: str, detector: dict[str, Any], url: str, evidence: list[str]) -> Candidate:
        return Candidate(title=detector["title"], category=category, detector=detector["name"], url=url, evidence=evidence, confidence=0.55 if evidence else 0.45)

    def _dedupe(self, candidates: list[Candidate]) -> list[Candidate]:
        seen: dict[tuple[str, str, str], Candidate] = {}
        for c in candidates:
            key = (c.category, c.detector, c.url)
            if key not in seen or c.confidence > seen[key].confidence:
                seen[key] = c
        return sorted(seen.values(), key=lambda c: (c.category, -c.confidence, c.title))

    def _markdown(self, payload: dict[str, Any]) -> str:
        lines = [f"# VulnScope Comprehensive Safe Review — {payload['target']}", "", "Review candidates only. No exploitation or state-changing validation was performed.", "", "## Summary", f"- Categories: `{payload['summary']['categories']}`", f"- Detectors: `{payload['summary']['detectors']}`", f"- Input URLs: `{payload['summary']['input_urls']}`", f"- Candidates: `{payload['summary']['candidates']}`", "", "## Detector Coverage"]
        for cat, count in payload["detectors_per_category"].items():
            lines.append(f"- `{cat}`: `{count}` detectors")
        lines += ["", "## Candidates"]
        for item in payload["candidates"][:120]:
            lines += [f"### {item['title']}", f"- Category: `{item['category']}`", f"- Detector: `{item['detector']}`", f"- URL: `{item['url']}`", f"- Status: `{item['validation_status']}` / `{item['exploit_status']}`", ""]
        if not payload["candidates"]:
            lines.append("No candidates found from available evidence.")
        return "\n".join(lines)

def run_comprehensive_suite(target: str | None = None) -> dict[str, Any]:
    return ComprehensiveCategorySuite(target=target).run()
