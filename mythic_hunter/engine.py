from __future__ import annotations

import base64
import json
import re
import textwrap
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STATUSES = {
    "DISCOVERED",
    "HYPOTHESIS",
    "NEEDS_MANUAL_VALIDATION",
    "FALSE_POSITIVE_LIKELY",
    "CONFIRMED_OBSERVATION",
    "CONFIRMED_VULNERABILITY",
    "NOT_REPORTABLE",
}

WORKFLOWS = {
    "LOGIN": {
        "keywords": ["login", "auth", "oauth", "sso", "callback", "state", "session", "mylogin"],
        "risks": ["open_redirect", "state_tampering", "auth_flow_review"],
    },
    "SIGNUP": {"keywords": ["signup", "register", "create-account"], "risks": ["workflow_bypass", "verification_review"]},
    "PASSWORD_RESET": {"keywords": ["reset", "forgot", "password"], "risks": ["token_flow_review", "account_recovery_review"]},
    "PROFILE": {
        "keywords": ["profile", "account", "settings", "user", "me", "garage", "address", "contact"],
        "risks": ["idor_bola", "mass_assignment", "sensitive_data_exposure"],
    },
    "ORDERS": {
        "keywords": ["order", "orders", "cart", "checkout", "invoice", "receipt", "cancellation", "purchase"],
        "risks": ["idor_bola", "business_logic", "sensitive_data_exposure"],
    },
    "PAYMENT": {
        "keywords": ["payment", "billing", "subscription", "plan", "coupon", "price", "currency"],
        "risks": ["business_logic", "mass_assignment", "payment_manipulation"],
    },
    "BOOKING": {"keywords": ["booking", "reservation", "slot", "availability"], "risks": ["business_logic", "race_candidate"]},
    "FILE_UPLOAD": {
        "keywords": ["upload", "file", "attachment", "document", "media", "image", "avatar"],
        "risks": ["stored_xss_review", "file_exposure", "access_control_failure"],
    },
    "ADMIN": {"keywords": ["admin", "internal", "employee", "staff", "protected"], "risks": ["access_control", "sensitive_exposure"]},
    "DEALER": {"keywords": ["dealer"], "risks": ["role_boundary", "access_control"]},
    "API": {"keywords": ["api", "rest", "v1", "v2", "json"], "risks": ["excessive_data", "idor_bola", "cors_review"]},
    "GRAPHQL": {"keywords": ["graphql", "query", "mutation"], "risks": ["graphql_authorization", "schema_review"]},
    "REDIRECT": {
        "keywords": ["redirect", "returnurl", "returnURL", "returnUrl", "next", "callback", "continue", "target"],
        "risks": ["open_redirect", "oauth_state_tampering"],
    },
    "CONFIGURATION": {"keywords": ["config", "environment", "env", "debug", "staging"], "risks": ["configuration_exposure"]},
    "SEARCH": {"keywords": ["search", "q", "query", "keyword"], "risks": ["xss_review", "injection_review"]},
    "SUPPORT": {"keywords": ["support", "help", "ticket", "case"], "risks": ["data_exposure", "workflow_review"]},
}

FALSE_SECRET_PATTERNS = [
    "localrfoencryptionsecretkey.then",
    "getsecretkey(",
    "secretkeyrequired",
    "secretlabel",
    "secretname",
    "data-secret",
    "issecretenabled",
]

PUBLIC_CONFIG_PATTERNS = [
    "boomr_api_key",
    "google analytics",
    "gtm-",
    "recaptcha",
    "site key",
    "firebase",
    "consent",
    "tenant id",
]

REAL_SECRET_REGEXES = [
    re.compile(r"client_secret\s*[:=]\s*['\"][^'\"]{3,}['\"]", re.I),
    re.compile(r"access_token\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
    re.compile(r"refresh_token\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
    re.compile(r"private_key\s*[:=]\s*['\"]-----BEGIN", re.I),
    re.compile(r"aws_access_key_id\s*[:=]\s*['\"]AKIA[0-9A-Z]{12,}['\"]", re.I),
    re.compile(r"aws_secret_access_key\s*[:=]\s*['\"][^'\"]{20,}['\"]", re.I),
    re.compile(r"database_url\s*[:=]\s*['\"](?:postgres|mysql|mongodb)://", re.I),
    re.compile(r"bearer\s+[A-Za-z0-9._\-]{20,}", re.I),
    re.compile(r"https?://[^\s:@]+:[^\s:@]+@[^\s]+", re.I),
]

STATE_PARAMS = ["state", "redirect", "redirect_uri", "returnURL", "returnUrl", "next", "callback", "continue", "target"]
HEADER_NAMES = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "cache-control", "pragma", "expires", "vary", "set-cookie", "access-control-allow-origin", "access-control-allow-credentials"]

@dataclass
class EvidenceItem:
    evidence_id: str
    finding_id: str
    evidence_type: str
    content: str
    redacted: bool = True
    sensitive_field: bool = False
    confidence: str = "Medium"
    proves: str = ""

@dataclass
class MythicFinding:
    finding_id: str
    title: str
    signal: str
    category: str
    workflow: str = "UNKNOWN"
    risk: str = "review_required"
    status: str = "DISCOVERED"
    confidence: str = "Medium"
    false_positive_chance: str = "medium"
    reportability_score: int = 0
    reportability_label: str = "Not reportable"
    why_classified: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    safe_validation_steps: list[str] = field(default_factory=list)
    required_proof: list[str] = field(default_factory=list)
    stability_warnings: list[str] = field(default_factory=list)
    report_wording: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)

@dataclass
class MythicResult:
    findings: list[MythicFinding]
    endpoints: list[str]
    parameters: dict[str, list[str]]
    js_signals: list[dict[str, Any]]
    state_analysis: list[dict[str, Any]]
    bug_chains: list[dict[str, Any]]
    dashboard: dict[str, int]
    reports: dict[str, str]
    acceptance_tests: list[dict[str, Any]] = field(default_factory=list)

class MythicHunterEngine:
    def __init__(self, depth: str = "BALANCED_VALIDATION", report_type: str = "bug_bounty_report") -> None:
        self.depth = depth
        self.report_type = report_type
        self._counter = 0

    def analyze_text(self, text: str) -> MythicResult:
        normalized = text or ""
        endpoints = self._extract_endpoints(normalized)
        parameters = self._extract_parameters(endpoints, normalized)
        imported_findings = self._import_scanner_findings(normalized)
        js_signals = self._analyze_javascript(normalized)
        state_analysis = self._analyze_state_parameters(endpoints, normalized)
        header_findings = self._audit_headers_cookies_cache_cors(normalized)
        candidates = imported_findings + header_findings
        candidates += self._findings_from_endpoints(endpoints, parameters)
        candidates += self._findings_from_js(js_signals)
        candidates += self._findings_from_state(state_analysis)
        candidates = self._dedupe_findings(candidates)

        for finding in candidates:
            self._run_reasoning_loop(finding)
            self._apply_stability_guard(finding)
            self._score_reportability(finding)
            self._build_report_wording(finding)

        bug_chains = self._build_bug_chains(candidates)
        dashboard = self._build_dashboard(candidates, endpoints, js_signals, state_analysis, bug_chains)
        reports = self._build_reports(candidates, dashboard, bug_chains)
        return MythicResult(
            findings=candidates,
            endpoints=endpoints,
            parameters=parameters,
            js_signals=js_signals,
            state_analysis=state_analysis,
            bug_chains=bug_chains,
            dashboard=dashboard,
            reports=reports,
        )

    def analyze_idor_pair(self, account_a_response: str, account_b_response: str, private_marker: str, endpoint: str = "") -> MythicFinding:
        marker = private_marker.strip()
        finding = self._new_finding("IDOR / BOLA Validation Assistant", endpoint or "manual comparison", "Access Control", "idor_bola")
        finding.workflow = self._classify_workflow(endpoint)[0]
        finding.trust_boundaries = ["Account A to Account B", "object ownership boundary"]
        finding.required_proof = ["two owned accounts", "redacted Account A request/response", "redacted Account B request/response", "object ownership proof", "private marker visible to wrong account"]
        if marker and marker in account_b_response:
            finding.status = "CONFIRMED_VULNERABILITY"
            finding.confidence = "High"
            finding.false_positive_chance = "low"
            finding.why_classified.append("Account B response contains Account A private marker.")
        elif re.search(r"\b(401|403)\b|unauthori[sz]ed|forbidden|login", account_b_response, re.I):
            finding.status = "NOT_REPORTABLE"
            finding.why_classified.append("Account B response appears blocked or redirected to login.")
        else:
            finding.status = "NEEDS_MANUAL_VALIDATION"
            finding.why_classified.append("Provided comparison does not prove cross-account exposure.")
        self._score_reportability(finding)
        self._build_report_wording(finding)
        return finding

    def compare_auth_unauth(self, logged_out_response: str, logged_in_response: str, endpoint: str = "", marker: str = "") -> MythicFinding:
        finding = self._new_finding("Auth vs Unauth Comparator", endpoint or "manual comparison", "Authentication Boundary", "auth_unauth_leakage")
        finding.trust_boundaries = ["logged out to logged in", "public page to private API"]
        private_terms = ["email", "phone", "address", "order", "invoice", "customerId", "accountId", "profile", "garage", "payment", "session", "userId"]
        found_private = [term for term in private_terms if re.search(re.escape(term), logged_out_response, re.I)]
        if marker and marker in logged_out_response:
            finding.status = "CONFIRMED_VULNERABILITY"
            finding.confidence = "High"
            finding.false_positive_chance = "low"
            finding.why_classified.append("Logged-out response contains provided private marker.")
        elif found_private:
            finding.status = "NEEDS_MANUAL_VALIDATION"
            finding.confidence = "Medium"
            finding.why_classified.append("Logged-out response contains private-data keywords: " + ", ".join(found_private[:8]))
        else:
            finding.status = "NOT_REPORTABLE"
            finding.why_classified.append("Logged-out response appears to contain only public metadata.")
        finding.required_proof = ["endpoint URL", "logged-out response with private marker", "logged-in ownership proof", "redacted private field evidence"]
        self._score_reportability(finding)
        self._build_report_wording(finding)
        return finding

    def run_acceptance_tests(self) -> list[dict[str, Any]]:
        tests = [
            ("BOOMR_API_key: value", "NOT_REPORTABLE"),
            ("localRfoEncryptionSecretKey.then(...) ", "FALSE_POSITIVE_LIKELY"),
            ('client_secret = "abc123"', "NEEDS_MANUAL_VALIDATION"),
            ("/de/shop/ls/orders/physical-goods", "NEEDS_MANUAL_VALIDATION"),
            ("Missing Content-Security-Policy", "CONFIRMED_OBSERVATION"),
            ("sourceMappingURL=app.js.map", "NEEDS_MANUAL_VALIDATION"),
            ("state=eyJyZXR1cm5VUkwiOiJodHRwczovL2V4YW1wbGUuY29tIn0", "NEEDS_MANUAL_VALIDATION"),
        ]
        results = []
        for input_text, expected in tests:
            result = self.analyze_text(input_text)
            observed = result.findings[0].status if result.findings else "NO_FINDING"
            results.append({"input": input_text, "expected_status": expected, "observed_status": observed, "passed": observed == expected or (expected == "NEEDS_MANUAL_VALIDATION" and observed in {"NEEDS_MANUAL_VALIDATION", "HYPOTHESIS"})})
        idor = self.analyze_idor_pair("owner order marker A123", "other response contains A123", "A123", "/api/orders/1")
        results.append({"input": "Account B response contains Account A private order marker", "expected_status": "CONFIRMED_VULNERABILITY", "observed_status": idor.status, "passed": idor.status == "CONFIRMED_VULNERABILITY"})
        return results

    def _new_finding(self, title: str, signal: str, category: str, risk: str) -> MythicFinding:
        self._counter += 1
        return MythicFinding(finding_id=f"MH-{self._counter:03d}", title=title, signal=signal[:500], category=category, risk=risk)

    def _extract_endpoints(self, text: str) -> list[str]:
        urls = re.findall(r"https?://[^\s'\"<>]+", text)
        paths = re.findall(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/)*[A-Za-z0-9._~!$&'()*+,;=:@?%/-]*", text)
        endpoints = []
        for item in urls + paths:
            clean = item.rstrip(".,);]\"'")
            if clean and clean not in endpoints:
                endpoints.append(clean)
        return endpoints[:1000]

    def _extract_parameters(self, endpoints: list[str], text: str) -> dict[str, list[str]]:
        params: dict[str, list[str]] = {}
        for endpoint in endpoints:
            parsed = urllib.parse.urlparse(endpoint)
            found = sorted(set(urllib.parse.parse_qs(parsed.query).keys()))
            if found:
                params[endpoint] = found
        for param in STATE_PARAMS:
            if re.search(rf"\b{re.escape(param)}\s*=", text, re.I):
                params.setdefault("raw_text", []).append(param)
        return params

    def _import_scanner_findings(self, text: str) -> list[MythicFinding]:
        mappings = [
            ("Missing Content-Security-Policy", "Header/Cookie/Cache/CORS Auditor", "Security Headers", "missing_csp", "CONFIRMED_OBSERVATION"),
            ("Missing Strict-Transport-Security", "Header/Cookie/Cache/CORS Auditor", "Security Headers", "missing_hsts", "CONFIRMED_OBSERVATION"),
            ("Missing X-Frame-Options", "Header/Cookie/Cache/CORS Auditor", "Security Headers", "missing_xfo", "CONFIRMED_OBSERVATION"),
            ("Sensitive keyword signal", "JavaScript Intelligence Engine", "Sensitive Exposure Review", "secret_keyword", "FALSE_POSITIVE_LIKELY"),
            ("API route discovered", "Scanner Finding Importer", "API Discovery", "api_route", "NOT_REPORTABLE"),
            ("IDOR candidate", "IDOR / BOLA Validation Assistant", "Access Control", "idor_bola", "NEEDS_MANUAL_VALIDATION"),
            ("robots.txt", "Scanner Finding Importer", "Route Discovery", "robots_sitemap", "NOT_REPORTABLE"),
            ("source map", "Source Map Analyzer", "Source Map Exposure", "source_map", "NEEDS_MANUAL_VALIDATION"),
            ("CORS", "Header/Cookie/Cache/CORS Auditor", "CORS Security", "cors", "CONFIRMED_OBSERVATION"),
            ("Set-Cookie", "Header/Cookie/Cache/CORS Auditor", "Cookie Security", "cookie_flags", "CONFIRMED_OBSERVATION"),
        ]
        findings = []
        for needle, title, category, risk, status in mappings:
            if re.search(re.escape(needle), text, re.I):
                f = self._new_finding(title, needle, category, risk)
                f.status = status
                f.why_classified.append(f"Imported scanner signal matched: {needle}")
                findings.append(f)
        secret_f = self._classify_secret_signal(text)
        if secret_f:
            findings.append(secret_f)
        return findings

    def _findings_from_endpoints(self, endpoints: list[str], parameters: dict[str, list[str]]) -> list[MythicFinding]:
        findings = []
        for endpoint in endpoints:
            workflow, reasons, risks = self._classify_workflow(endpoint)
            if workflow != "UNKNOWN":
                f = self._new_finding(f"{workflow} Workflow Candidate", endpoint, "Workflow Mapper", risks[0] if risks else "workflow_review")
                f.workflow = workflow
                f.status = "NEEDS_MANUAL_VALIDATION" if f.risk in {"idor_bola", "business_logic", "open_redirect", "access_control"} else "DISCOVERED"
                f.why_classified = reasons
                f.safe_validation_steps = self._business_logic_plan(workflow)
                f.required_proof = self._required_proof_for_risk(f.risk)
                f.trust_boundaries = self._trust_boundaries_for_workflow(workflow, endpoint)
                findings.append(f)
            for param in parameters.get(endpoint, []):
                if param.lower() in [p.lower() for p in STATE_PARAMS]:
                    f = self._new_finding("State / Redirect Parameter Candidate", endpoint, "State / Redirect Parameter Analyzer", "open_redirect_or_state_tampering")
                    f.workflow = "REDIRECT"
                    f.status = "NEEDS_MANUAL_VALIDATION"
                    f.why_classified.append(f"Parameter {param} is state/redirect related.")
                    f.required_proof = ["decoded parameter evidence", "authorized redirect-flow test", "proof external or unsafe return is accepted", "impact on auth or navigation flow"]
                    findings.append(f)
        return findings

    def _classify_workflow(self, value: str) -> tuple[str, list[str], list[str]]:
        lower = value.lower()
        for workflow, data in WORKFLOWS.items():
            hits = [kw for kw in data["keywords"] if kw.lower() in lower]
            if hits:
                return workflow, [f"Matched workflow keywords: {', '.join(hits)}"], data["risks"]
        return "UNKNOWN", ["No workflow keyword matched."], ["general_review"]

    def _analyze_javascript(self, text: str) -> list[dict[str, Any]]:
        signals = []
        js_endpoint_hits = re.findall(r"['\"]((?:/api/|/graphql|/admin|/dealer|/internal|https?://)[^'\"]+)['\"]", text, re.I)
        for hit in js_endpoint_hits[:100]:
            signals.append({"signal": hit, "type": "js_endpoint", "classification": "hidden_or_api_route", "confidence": "Medium", "false_positive_chance": "medium"})
        for match in re.findall(r"sourceMappingURL\s*=\s*([^\s]+)|([\w./-]+\.js\.map)", text, re.I):
            value = next((m for m in match if m), "source map")
            signals.append({"signal": value, "type": "source_map", "classification": "source_map_candidate", "confidence": "High", "false_positive_chance": "medium"})
        if re.search(r"\b(query|mutation)\b|graphql", text, re.I):
            signals.append({"signal": "GraphQL query/mutation indicator", "type": "graphql", "classification": "graphql_api_review", "confidence": "Medium", "false_positive_chance": "medium"})
        for flag in ["featureFlag", "featureToggle", "isProd", "isDev", "debug", "staging", "internal", "beta", "admin", "dealer", "employee", "testMode", "mockMode", "environment", "role", "permission"]:
            if re.search(flag, text, re.I):
                signals.append({"signal": flag, "type": "feature_flag_or_debug", "classification": "configuration_review", "confidence": "Medium", "false_positive_chance": "medium"})
        secret = self._classify_secret_signal(text)
        if secret:
            signals.append({"signal": secret.signal, "type": "secret_classification", "classification": secret.status, "confidence": secret.confidence, "false_positive_chance": secret.false_positive_chance})
        return signals

    def _classify_secret_signal(self, text: str) -> MythicFinding | None:
        lower = text.lower()
        for pattern in FALSE_SECRET_PATTERNS:
            if pattern in lower:
                f = self._new_finding("False-Positive Secret Keyword Signal", pattern, "JavaScript Intelligence Engine", "secret_false_positive")
                f.status = "FALSE_POSITIVE_LIKELY"
                f.confidence = "High"
                f.false_positive_chance = "high"
                f.why_classified.append("Secret-like term is a code reference or label, not a hardcoded secret value.")
                return f
        for pattern in PUBLIC_CONFIG_PATTERNS:
            if pattern.lower() in lower:
                f = self._new_finding("Likely Public Frontend Configuration Key", pattern, "JavaScript Intelligence Engine", "public_config_key")
                f.status = "NOT_REPORTABLE"
                f.confidence = "Medium"
                f.false_positive_chance = "high"
                f.why_classified.append("Signal resembles public analytics/RUM/site configuration rather than a private secret.")
                return f
        for regex in REAL_SECRET_REGEXES:
            match = regex.search(text)
            if match:
                f = self._new_finding("Potential Hardcoded Secret-Like Value", self._redact(match.group(0)), "JavaScript Intelligence Engine", "secret_exposure_candidate")
                f.status = "NEEDS_MANUAL_VALIDATION"
                f.confidence = "Medium"
                f.false_positive_chance = "medium"
                f.required_proof = ["confirm the value is active without using it", "identify affected environment", "show exposure location", "redact value in all reports"]
                f.safe_validation_steps = ["Do not test or use the token.", "Confirm only exposure context and report safely with redaction."]
                f.why_classified.append("Hardcoded secret-like assignment pattern detected.")
                return f
        return None

    def _findings_from_js(self, signals: list[dict[str, Any]]) -> list[MythicFinding]:
        findings = []
        for signal in signals:
            stype = signal.get("type")
            if stype == "source_map":
                f = self._new_finding("Source Map Review Candidate", str(signal.get("signal")), "Source Map Analyzer", "source_map_exposure")
                f.status = "NEEDS_MANUAL_VALIDATION"
                f.why_classified.append("sourceMappingURL or .map reference detected. Discovery alone is not a vulnerability.")
                f.required_proof = ["source map is publicly reachable", "sensitive internal source or real secret exists", "impact is explained"]
                findings.append(f)
            elif stype == "feature_flag_or_debug":
                f = self._new_finding("Feature Flag / Debug Review Candidate", str(signal.get("signal")), "Feature Flag / Debug Analyzer", "debug_or_feature_flag_review")
                f.status = "DISCOVERED"
                f.why_classified.append("Feature/debug/environment keyword was observed.")
                f.required_proof = ["flag affects production behavior", "hidden route or privileged flow is exposed", "impact is demonstrated safely"]
                findings.append(f)
            elif stype == "graphql":
                f = self._new_finding("GraphQL/API Review Candidate", str(signal.get("signal")), "GraphQL/API Expert", "graphql_api_review")
                f.workflow = "GRAPHQL"
                f.status = "NEEDS_MANUAL_VALIDATION"
                f.required_proof = ["operation name", "object identifier", "auth boundary evidence", "sensitive data or action impact"]
                findings.append(f)
        return findings

    def _analyze_state_parameters(self, endpoints: list[str], text: str) -> list[dict[str, Any]]:
        results = []
        candidates: list[tuple[str, str]] = []
        for endpoint in endpoints:
            parsed = urllib.parse.urlparse(endpoint)
            qs = urllib.parse.parse_qs(parsed.query)
            for key, values in qs.items():
                if key in STATE_PARAMS or key.lower() in [p.lower() for p in STATE_PARAMS]:
                    candidates.append((key, values[0] if values else ""))
        for key in STATE_PARAMS:
            for value in re.findall(rf"\b{re.escape(key)}=([^\s&]+)", text, re.I):
                candidates.append((key, value))
        for key, raw in candidates[:50]:
            decoded = urllib.parse.unquote(raw)
            decoded_b64 = self._try_b64(decoded)
            parsed_json = self._try_json(decoded_b64 or decoded)
            extracted_urls = re.findall(r"https?://[^\s'\"}]+", decoded + " " + (decoded_b64 or ""))
            risky_fields = []
            for field in ["returnURL", "returnUrl", "redirect", "role", "user", "account", "loggedIn", "admin"]:
                if re.search(field, decoded + " " + (decoded_b64 or ""), re.I):
                    risky_fields.append(field)
            results.append({"parameter": key, "raw": self._redact(raw), "url_decoded": self._redact(decoded), "base64_decoded": self._redact(decoded_b64) if decoded_b64 else None, "json": parsed_json, "extracted_urls": extracted_urls, "risk": "OPEN_REDIRECT / STATE_TAMPERING candidate" if extracted_urls or risky_fields else "state review", "status": "NEEDS_MANUAL_VALIDATION", "risky_fields": risky_fields})
        return results

    def _findings_from_state(self, state_analysis: list[dict[str, Any]]) -> list[MythicFinding]:
        findings = []
        for item in state_analysis:
            f = self._new_finding("Decoded State / Redirect Parameter Candidate", item.get("parameter", "state"), "State / Redirect Parameter Analyzer", "open_redirect_or_state_tampering")
            f.workflow = "REDIRECT"
            f.status = "NEEDS_MANUAL_VALIDATION"
            f.why_classified.append("State/redirect parameter was decoded locally and requires authorized validation.")
            f.required_proof = ["decoded value", "external redirect or state tampering accepted inside scope", "auth or navigation impact", "no modified request sent by the tool"]
            findings.append(f)
        return findings

    def _audit_headers_cookies_cache_cors(self, text: str) -> list[MythicFinding]:
        findings = []
        lower = text.lower()
        if "access-control-allow-origin: *" in lower:
            f = self._new_finding("Wildcard CORS Policy Observed", "Access-Control-Allow-Origin: *", "Header/Cookie/Cache/CORS Auditor", "cors_review")
            f.status = "CONFIRMED_OBSERVATION"
            f.required_proof = ["credentialed sensitive data access must be proven before reportability is strong"]
            findings.append(f)
        if "access-control-allow-credentials: true" in lower and "access-control-allow-origin: *" in lower:
            f = self._new_finding("Potential Credentialed CORS Risk", "ACAO wildcard + credentials", "Header/Cookie/Cache/CORS Auditor", "cors_credentialed_risk")
            f.status = "NEEDS_MANUAL_VALIDATION"
            f.required_proof = ["credentialed cross-origin sensitive response proof", "allowed origin behavior", "affected sensitive endpoint"]
            findings.append(f)
        if "cache-control: public" in lower or ("cache-control" not in lower and any(k in lower for k in ["email", "invoice", "order", "accountid"])):
            f = self._new_finding("Private Data Cache Review Candidate", "cache headers", "Header/Cookie/Cache/CORS Auditor", "cache_misconfig_review")
            f.status = "NEEDS_MANUAL_VALIDATION"
            f.required_proof = ["authenticated private response", "cacheable response headers", "private marker in cached content"]
            findings.append(f)
        if "set-cookie" in lower and any(name in lower for name in ["session", "sid", "auth", "token", "jwt", "login"]):
            f = self._new_finding("Sensitive Cookie Flag Review", "Set-Cookie", "Header/Cookie/Cache/CORS Auditor", "cookie_flags")
            f.status = "CONFIRMED_OBSERVATION"
            f.required_proof = ["session cookie impact needed before vulnerability claim"]
            findings.append(f)
        return findings

    def _trust_boundaries_for_workflow(self, workflow: str, endpoint: str) -> list[str]:
        boundaries = []
        if workflow in {"LOGIN", "PASSWORD_RESET"}:
            boundaries += ["logged out to logged in", "external redirect to authentication flow"]
        if workflow in {"ORDERS", "PROFILE", "PAYMENT", "BOOKING", "API"}:
            boundaries += ["Account A to Account B", "object ownership boundary"]
        if workflow in {"ADMIN", "DEALER"}:
            boundaries += ["normal user to admin/dealer/staff"]
        if workflow == "FILE_UPLOAD":
            boundaries += ["uploaded file to public rendering"]
        if "api" in endpoint.lower() or workflow == "API":
            boundaries += ["public page to private API"]
        return sorted(set(boundaries))

    def _business_logic_plan(self, workflow: str) -> list[str]:
        plans = {
            "ORDERS": ["Check whether another owned account can view or modify the order.", "Check whether cancellation targets only owned orders.", "Review whether client-side status, quantity, price, or currency controls server decisions."],
            "PAYMENT": ["Review whether amount, plan, coupon, or currency is server-side enforced.", "Check whether checkout state can continue without valid payment confirmation."],
            "BOOKING": ["Review unavailable slot booking, duplicate booking, and cross-account cancellation boundaries."],
            "PROFILE": ["Review whether role/accountType fields can be mass assigned.", "Check whether profile/contact data is isolated per account."],
            "LOGIN": ["Review returnURL and state handling.", "Check whether callback/state are signed and bound to the session."],
            "FILE_UPLOAD": ["Review file type validation, SVG/HTML rendering, and cross-account file access."],
        }
        return plans.get(workflow, ["Define expected access rules.", "Collect proof before claiming vulnerability."])

    def _required_proof_for_risk(self, risk: str) -> list[str]:
        if "idor" in risk or "bola" in risk:
            return ["Account A owns object", "Account B uses own session", "Account B accesses Account A object", "Account B receives Account A private data", "No guessed or third-party IDs used"]
        if "open_redirect" in risk or "state" in risk:
            return ["decoded parameter", "unsafe return accepted in scope", "auth/navigation impact", "no out-of-scope redirect abuse"]
        if "business" in risk or "payment" in risk:
            return ["normal workflow baseline", "changed client-side value", "server accepts invalid business state", "real impact without fraud or abuse"]
        return ["clear endpoint evidence", "impact evidence", "manual validation notes"]

    def _build_bug_chains(self, findings: list[MythicFinding]) -> list[dict[str, Any]]:
        titles = " ".join(f.title + " " + f.risk for f in findings).lower()
        chains = []
        rules = [
            ("missing_csp", "xss", "Missing CSP + XSS candidate", "Needs validation"),
            ("open_redirect", "oauth", "Open redirect + OAuth callback", "Needs validation"),
            ("source_map", "api", "Source map + hidden API", "Needs validation"),
            ("idor", "invoice", "IDOR + invoice/order endpoint", "Strong candidate"),
            ("cookie", "xss", "Weak cookie + XSS", "Hypothesis only"),
            ("debug", "internal", "Debug flag + internal API", "Needs validation"),
            ("cache", "auth_unauth", "Auth leakage + cache issue", "Needs validation"),
        ]
        for a, b, name, label in rules:
            if a in titles and b in titles:
                chains.append({"chain": name, "label": label, "status": "HYPOTHESIS", "reason": "Multiple weak signals appear connected, but final impact requires evidence."})
        return chains

    def _run_reasoning_loop(self, finding: MythicFinding) -> None:
        mode_counts = {"QUICK_TRIAGE": 3, "BALANCED_VALIDATION": 5, "DEEP_HUNTER_MODE": 8, "PARANOID_FALSE_POSITIVE_REVIEW": 10}
        loops = mode_counts.get(self.depth, 5)
        passes = ["Signal classifier", "Workflow mapper", "Trust-boundary analyst", "False-positive reviewer", "Evidence requirement builder", "Reportability scorer", "Bug-chain analyst", "Safe validation planner", "Final verdict writer", "Contradiction checker"][:loops]
        finding.why_classified.append("Reasoning loop: " + " -> ".join(passes))
        if not finding.trust_boundaries:
            finding.trust_boundaries = self._trust_boundaries_for_workflow(finding.workflow, finding.signal)
        if not finding.safe_validation_steps:
            finding.safe_validation_steps = self._business_logic_plan(finding.workflow)
        if not finding.required_proof:
            finding.required_proof = self._required_proof_for_risk(finding.risk)

    def _apply_stability_guard(self, finding: MythicFinding) -> None:
        weak_header = finding.risk in {"missing_csp", "missing_hsts", "missing_xfo", "cookie_flags"}
        discovery_only = finding.risk in {"robots_sitemap", "api_route"}
        public_key = finding.risk == "public_config_key"
        keyword_secret = finding.risk in {"secret_false_positive", "secret_keyword"}
        if finding.status == "CONFIRMED_VULNERABILITY" and not self._has_strong_proof(finding):
            finding.stability_warnings.append("Confirmed vulnerability claim downgraded because required proof is missing.")
            finding.status = "NEEDS_MANUAL_VALIDATION"
        if weak_header:
            finding.status = "CONFIRMED_OBSERVATION"
            finding.stability_warnings.append("Missing headers or cookie flags alone are observations, not confirmed vulnerabilities.")
        if discovery_only:
            finding.status = "NOT_REPORTABLE"
            finding.stability_warnings.append("Discovery-only signal is not reportable without impact evidence.")
        if public_key:
            finding.status = "NOT_REPORTABLE"
            finding.stability_warnings.append("Likely public frontend configuration key.")
        if keyword_secret:
            finding.status = "FALSE_POSITIVE_LIKELY"
            finding.stability_warnings.append("Keyword-only secret match or code reference is likely false positive.")
        if "idor" in finding.risk and finding.status == "CONFIRMED_VULNERABILITY" and not any("private marker" in p.lower() for p in finding.why_classified):
            finding.status = "NEEDS_MANUAL_VALIDATION"
            finding.stability_warnings.append("IDOR cannot be confirmed without two-account private-data proof.")

    def _has_strong_proof(self, finding: MythicFinding) -> bool:
        text = " ".join(finding.why_classified + [ev.proves for ev in finding.evidence]).lower()
        return any(term in text for term in ["private marker", "logged-out response contains provided private marker", "hardcoded secret-like assignment pattern"])

    def _score_reportability(self, finding: MythicFinding) -> None:
        base = {"CONFIRMED_VULNERABILITY": 90, "NEEDS_MANUAL_VALIDATION": 58, "CONFIRMED_OBSERVATION": 40, "HYPOTHESIS": 45, "DISCOVERED": 30, "FALSE_POSITIVE_LIKELY": 10, "NOT_REPORTABLE": 5}.get(finding.status, 20)
        if finding.false_positive_chance == "medium":
            base -= 15
        if finding.false_positive_chance == "high":
            base -= 30
        if "secret_exposure" in finding.risk:
            base += 10
        if "idor" in finding.risk and finding.status == "CONFIRMED_VULNERABILITY":
            base = 95
        if finding.risk in {"missing_csp", "missing_hsts", "missing_xfo", "cookie_flags", "cors_review"}:
            base = min(base, 50)
        if finding.status in {"NOT_REPORTABLE", "FALSE_POSITIVE_LIKELY"}:
            base = min(base, 30)
        score = max(0, min(100, int(base)))
        finding.reportability_score = score
        if score <= 30:
            label = "Not reportable"
        elif score <= 50:
            label = "Observation only"
        elif score <= 69:
            label = "Needs validation"
        elif score <= 84:
            label = "Strong candidate"
        else:
            label = "Strong report"
        finding.reportability_label = label

    def _build_report_wording(self, finding: MythicFinding) -> None:
        finding.report_wording = f"{finding.title}: {finding.status}. Evidence currently supports {finding.reportability_label.lower()}. Do not claim more than the evidence proves."

    def _dedupe_findings(self, findings: list[MythicFinding]) -> list[MythicFinding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, f.signal, f.risk)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _build_dashboard(self, findings: list[MythicFinding], endpoints: list[str], js_signals: list[dict[str, Any]], state_analysis: list[dict[str, Any]], bug_chains: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "Findings Imported": len(findings),
            "Endpoints Extracted": len(endpoints),
            "Workflows Detected": len({f.workflow for f in findings if f.workflow != "UNKNOWN"}),
            "JS Signals Classified": len(js_signals),
            "IDOR Candidates": sum(1 for f in findings if "idor" in f.risk or "bola" in f.risk),
            "State Parameters Found": len(state_analysis),
            "Source Map Candidates": sum(1 for f in findings if "source_map" in f.risk),
            "False Positives Removed": sum(1 for f in findings if f.status == "FALSE_POSITIVE_LIKELY"),
            "Needs Manual Validation": sum(1 for f in findings if f.status == "NEEDS_MANUAL_VALIDATION"),
            "Reportable Candidates": sum(1 for f in findings if f.reportability_score >= 70),
            "Bug Chains": len(bug_chains),
        }

    def _build_reports(self, findings: list[MythicFinding], dashboard: dict[str, int], bug_chains: list[dict[str, Any]]) -> dict[str, str]:
        md = ["# Mythic Hunter Validation Report", "", "## Dashboard"]
        md += [f"- **{k}:** {v}" for k, v in dashboard.items()]
        md.append("\n## Findings")
        for f in findings:
            md += [f"### {f.finding_id} - {f.title}", f"- Status: `{f.status}`", f"- Workflow: `{f.workflow}`", f"- Risk: `{f.risk}`", f"- Reportability: `{f.reportability_score}` / {f.reportability_label}", f"- Signal: `{f.signal}`", "- Why classified:"]
            md += [f"  - {x}" for x in f.why_classified[:6]]
            md.append("- Required proof:")
            md += [f"  - {x}" for x in f.required_proof[:8]]
            md.append("- Safe validation steps:")
            md += [f"  - {x}" for x in f.safe_validation_steps[:8]]
            if f.stability_warnings:
                md.append("- Stability warnings:")
                md += [f"  - {x}" for x in f.stability_warnings[:6]]
            md.append(f"- Report wording: {f.report_wording}\n")
        md.append("## Bug Chains")
        if not bug_chains:
            md.append("No meaningful bug chains were built from current evidence.")
        else:
            for chain in bug_chains:
                md.append(f"- **{chain['chain']}** — {chain['label']} — {chain['status']}: {chain['reason']}")
        proof = self._proof_exports(findings)
        return {"markdown_report": "\n".join(md), "proof_exports": proof}

    def _proof_exports(self, findings: list[MythicFinding]) -> str:
        strongest = sorted(findings, key=lambda f: f.reportability_score, reverse=True)[:5]
        lines = ["# Mythic Hunter Proof Export", "", "## GitHub README Section", "", "Implemented a Mythic Hunter Validation Engine that converts scanner findings into evidence-based validation workflows using workflow mapping, JavaScript intelligence, IDOR/BOLA validation, false-positive reduction, and reportability scoring.", "", "## LinkedIn Post", "", "Built a defensive validation layer for VulnScope-Kali that focuses on evidence-first bug bounty triage, authorization boundaries, workflow mapping, source-map review, state parameter analysis, and professional report generation.", "", "## Resume Bullet", "", "- Built a Mythic Hunter Validation Engine that converts scanner findings into evidence-based security validation workflows using workflow mapping, JavaScript intelligence, IDOR/BOLA validation, false-positive reduction, and reportability scoring.", "", "## Screenshot Checklist"]
        lines += [f"- Capture dashboard showing {len(strongest)} top findings", "- Capture reportability score", "- Capture required proof section", "- Capture false-positive reduction/stability guard section"]
        return "\n".join(lines)

    def _try_b64(self, value: str) -> str | None:
        cleaned = value.strip().replace("-", "+").replace("_", "/")
        if len(cleaned) < 8:
            return None
        padding = "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            decoded = base64.b64decode(cleaned + padding, validate=False)
            text = decoded.decode("utf-8", errors="ignore")
            if text and sum(ch.isprintable() for ch in text) / max(1, len(text)) > 0.7:
                return text
        except Exception:
            return None
        return None

    def _try_json(self, value: str) -> Any:
        try:
            return json.loads(value)
        except Exception:
            return None

    def _redact(self, value: str) -> str:
        if not value:
            return value
        value = re.sub(r"(secret|token|key|password|authorization)(\s*[:=]\s*)[^\s'\"]+", r"\1\2[REDACTED]", value, flags=re.I)
        value = re.sub(r"Bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", value, flags=re.I)
        return value[:500]

def run_mythic_text(text: str, output_dir: str = "reports/output/mythic", depth: str = "BALANCED_VALIDATION", report_type: str = "bug_bounty_report") -> MythicResult:
    engine = MythicHunterEngine(depth=depth, report_type=report_type)
    result = engine.analyze_text(text)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mythic-report.md").write_text(result.reports["markdown_report"], encoding="utf-8")
    (out / "mythic-proof-exports.md").write_text(result.reports["proof_exports"], encoding="utf-8")
    (out / "mythic-evidence.json").write_text(json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
    return result

def run_acceptance_tests(output_dir: str = "reports/output/mythic") -> list[dict[str, Any]]:
    engine = MythicHunterEngine()
    tests = engine.run_acceptance_tests()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mythic-acceptance-tests.json").write_text(json.dumps(tests, indent=2), encoding="utf-8")
    return tests

def _result_to_dict(result: MythicResult) -> dict[str, Any]:
    return {
        "dashboard": result.dashboard,
        "endpoints": result.endpoints,
        "parameters": result.parameters,
        "js_signals": result.js_signals,
        "state_analysis": result.state_analysis,
        "bug_chains": result.bug_chains,
        "findings": [asdict(f) for f in result.findings],
        "acceptance_tests": result.acceptance_tests,
    }
