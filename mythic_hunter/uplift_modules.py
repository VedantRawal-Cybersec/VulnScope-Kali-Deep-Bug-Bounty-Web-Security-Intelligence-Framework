from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class UpliftFinding:
    title: str
    category: str
    signal: str
    status: str
    confidence: str
    reason: str
    safe_next_steps: list[str] = field(default_factory=list)
    evidence_required: list[str] = field(default_factory=list)


@dataclass
class UpliftResult:
    imports: dict[str, Any]
    object_flows: list[dict[str, Any]]
    state_actions: list[dict[str, Any]]
    graphql: list[dict[str, Any]]
    openapi: list[dict[str, Any]]
    jwt_session: list[dict[str, Any]]
    cloud: list[dict[str, Any]]
    cache: list[dict[str, Any]]
    mobile_api: list[dict[str, Any]]
    quality_gate: dict[str, Any]
    defensive_exports: dict[str, str]
    findings: list[UpliftFinding]


class UpliftModules:
    def analyze(self, text: str) -> UpliftResult:
        data = self._try_json(text)
        imports = self._import_everything(text, data)
        object_flows = self._object_flow_mapper(imports)
        state_actions = self._state_changing_detector(imports)
        graphql = self._graphql_analyzer(text)
        openapi = self._openapi_analyzer(data)
        jwt_session = self._jwt_session_analyzer(text)
        cloud = self._cloud_exposure_intelligence(text)
        cache = self._cache_review(text)
        mobile_api = self._mobile_api_recon(imports, text)
        findings: list[UpliftFinding] = []
        findings += self._findings_from_object_flow(object_flows)
        findings += self._findings_from_state_actions(state_actions)
        findings += self._findings_from_graphql(graphql)
        findings += self._findings_from_openapi(openapi)
        findings += self._findings_from_jwt(jwt_session)
        findings += self._findings_from_cloud(cloud)
        findings += self._findings_from_cache(cache)
        findings += self._findings_from_mobile(mobile_api)
        quality_gate = self._report_quality_gate(findings)
        defensive_exports = self._defensive_exports(findings)
        return UpliftResult(imports, object_flows, state_actions, graphql, openapi, jwt_session, cloud, cache, mobile_api, quality_gate, defensive_exports, findings)

    def _try_json(self, text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return None

    def _import_everything(self, text: str, data: Any) -> dict[str, Any]:
        urls = sorted(set(re.findall(r"https?://[^\s'\"<>]+", text)))
        paths = sorted(set(re.findall(r"(?<![A-Za-z0-9])/(?:api/|graphql|v1/|v2/|admin|orders|users|account|profile|payment|booking|upload|auth|oauth|callback|checkout|cart|invoice|files?)[A-Za-z0-9._~!$&'()*+,;=:@?%/\-]*", text, re.I)))
        headers = self._parse_headers(text)
        har_entries: list[dict[str, Any]] = []
        postman_items: list[dict[str, Any]] = []
        openapi_paths: list[str] = []
        if isinstance(data, dict):
            if isinstance(data.get("log"), dict):
                for entry in data["log"].get("entries", []):
                    req = entry.get("request", {})
                    res = entry.get("response", {})
                    har_entries.append({"url": req.get("url"), "method": req.get("method"), "status": res.get("status")})
            if "item" in data:
                postman_items = self._walk_postman_items(data.get("item", []))
            if isinstance(data.get("paths"), dict):
                openapi_paths = list(data["paths"].keys())
        endpoints = sorted(set([u.rstrip(".,);]") for u in urls + paths + [e.get("url") for e in har_entries if e.get("url")] + openapi_paths]))
        params: dict[str, list[str]] = {}
        for endpoint in endpoints:
            parsed = urllib.parse.urlparse(endpoint)
            found = sorted(set(urllib.parse.parse_qs(parsed.query).keys()))
            if found:
                params[endpoint] = found
        return {"endpoints": endpoints, "parameters": params, "headers": headers, "har_entries": har_entries, "postman_items": postman_items, "openapi_paths": openapi_paths}

    def _parse_headers(self, text: str) -> dict[str, str]:
        headers = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if key in {"cache-control", "pragma", "expires", "vary", "set-cookie", "access-control-allow-origin", "access-control-allow-credentials", "content-security-policy", "strict-transport-security", "x-frame-options", "referrer-policy", "x-cache", "cf-cache-status"}:
                headers[key] = value.strip()
        return headers

    def _walk_postman_items(self, items: list[Any]) -> list[dict[str, Any]]:
        output = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                output.extend(self._walk_postman_items(item.get("item", [])))
            request = item.get("request")
            if isinstance(request, dict):
                url = request.get("url")
                raw_url = url.get("raw") if isinstance(url, dict) else str(url)
                output.append({"name": item.get("name"), "method": request.get("method"), "url": raw_url})
        return output

    def _object_flow_mapper(self, imports: dict[str, Any]) -> list[dict[str, Any]]:
        items = []
        for endpoint in imports["endpoints"]:
            lower = endpoint.lower()
            id_fields = re.findall(r"(?:^|[/?&_.-])(order|invoice|user|account|profile|payment|booking|file|customer)[_-]?id(?:=|/|$)?", lower)
            role = "consumer_candidate" if id_fields or re.search(r"/[0-9a-f]{6,}(?:/|$)|/\d+(?:/|$)", lower) else "producer_candidate"
            if id_fields or role == "consumer_candidate" or re.search(r"/orders$|/users$|/invoices$|/profile$|/list|/search", lower):
                items.append({"endpoint": endpoint, "object_types": sorted(set(id_fields)) or ["unknown"], "role": role})
        return items

    def _state_changing_detector(self, imports: dict[str, Any]) -> list[dict[str, Any]]:
        verbs = ["cancel", "delete", "update", "approve", "reject", "transfer", "refund", "invite", "assign", "remove", "verify", "redeem", "checkout", "coupon", "change"]
        hits = []
        for endpoint in imports["endpoints"]:
            matched = [v for v in verbs if v in endpoint.lower()]
            if matched:
                hits.append({"endpoint": endpoint, "actions": matched, "status": "NEEDS_MANUAL_VALIDATION", "risk": "state_changing_action_review"})
        return hits

    def _graphql_analyzer(self, text: str) -> list[dict[str, Any]]:
        hits = []
        if "graphql" in text.lower():
            hits.append({"type": "endpoint", "signal": "graphql", "risk": "GraphQL surface review"})
        for op_type, name in re.findall(r"\b(query|mutation)\s+([A-Za-z0-9_]+)", text):
            risk = "state_changing_mutation_review" if op_type == "mutation" else "query_authorization_review"
            hits.append({"type": op_type, "operation": name, "risk": risk, "status": "NEEDS_MANUAL_VALIDATION"})
        for field in re.findall(r"\b(orderId|userId|accountId|invoiceId|customerId|profileId)\b", text, re.I):
            hits.append({"type": "object_id", "field": field, "risk": "object_authorization_review"})
        return hits

    def _openapi_analyzer(self, data: Any) -> list[dict[str, Any]]:
        results = []
        if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
            return results
        for path, methods in data["paths"].items():
            if not isinstance(methods, dict):
                continue
            for method, spec in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                params = [p.get("name") for p in spec.get("parameters", []) if isinstance(spec, dict) and isinstance(p, dict) and p.get("name")]
                risk = []
                if method.lower() in {"post", "put", "patch", "delete"}:
                    risk.append("state_changing_action")
                if any(str(p).lower().endswith("id") for p in params) or re.search(r"\{[^}]*id[^}]*\}", path, re.I):
                    risk.append("object_authorization_review")
                results.append({"path": path, "method": method.upper(), "parameters": params, "risk": risk or ["api_review"]})
        return results

    def _jwt_session_analyzer(self, text: str) -> list[dict[str, Any]]:
        results = []
        for candidate in re.findall(r"eyJ[A-Za-z0-9_\-.]+", text):
            parts = candidate.split(".")
            if len(parts) < 2:
                continue
            header = self._decode_jwt_part(parts[0])
            payload = self._decode_jwt_part(parts[1])
            if header or payload:
                results.append({"type": "jwt", "header": header, "payload_keys": sorted(list(payload.keys())) if isinstance(payload, dict) else [], "status": "CONFIRMED_OBSERVATION", "risk": "session_claim_review"})
        if re.search(r"Set-Cookie:.*(session|sid|auth|jwt)", text, re.I):
            cookie_line = " ".join(re.findall(r"Set-Cookie:.*", text, re.I))
            missing = [attr for attr in ["Secure", "HttpOnly", "SameSite"] if attr.lower() not in cookie_line.lower()]
            if missing:
                results.append({"type": "cookie", "missing_flags": missing, "status": "CONFIRMED_OBSERVATION", "risk": "cookie_posture_review"})
        return results

    def _decode_jwt_part(self, value: str) -> Any:
        import base64
        try:
            padded = value + "=" * ((4 - len(value) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))
        except Exception:
            return None

    def _cloud_exposure_intelligence(self, text: str) -> list[dict[str, Any]]:
        patterns = {
            "s3_bucket": r"https?://[A-Za-z0-9._\-]+\.s3[.-][^\s'\"]+",
            "gcs_bucket": r"https?://storage\.googleapis\.com/[^\s'\"]+",
            "azure_blob": r"https?://[A-Za-z0-9-]+\.blob\.core\.windows\.net/[^\s'\"]+",
            "firebase_config": r"firebase[A-Za-z0-9_\-]*\s*[:=]",
            "supabase_url": r"https?://[A-Za-z0-9]+\.supabase\.co",
            "cdn_header": r"(cloudfront|akamai|fastly|cf-cache-status|x-cache)",
        }
        hits = []
        for kind, pattern in patterns.items():
            for match in re.findall(pattern, text, re.I):
                hits.append({"type": kind, "signal": str(match)[:180], "status": "DISCOVERED", "risk": "cloud_exposure_review"})
        return hits

    def _cache_review(self, text: str) -> list[dict[str, Any]]:
        headers = self._parse_headers(text)
        findings = []
        private_markers = bool(re.search(r"email|phone|address|invoice|order|accountId|customerId|payment", text, re.I))
        cc = headers.get("cache-control", "")
        if private_markers and ("public" in cc.lower() or not cc):
            findings.append({"type": "private_cache_candidate", "cache_control": cc or "missing", "status": "NEEDS_MANUAL_VALIDATION", "risk": "private_data_cache_review"})
        if any(k in headers for k in ["x-cache", "cf-cache-status", "vary"]):
            findings.append({"type": "cache_behavior", "headers": headers, "status": "DISCOVERED", "risk": "cache_behavior_review"})
        return findings

    def _mobile_api_recon(self, imports: dict[str, Any], text: str) -> list[dict[str, Any]]:
        terms = ["android", "ios", "apk", "mobile", "okhttp", "retrofit", "bundle id", "package_name", "postman"]
        if not any(term in text.lower() for term in terms) and not imports.get("postman_items"):
            return []
        return [{"endpoint": e, "source": "mobile_or_collection_input", "risk": "mobile_api_review", "status": "DISCOVERED"} for e in imports["endpoints"][:100]]

    def _findings_from_object_flow(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("ObjectFlow Mapper Candidate", "Authorization", i["endpoint"], "NEEDS_MANUAL_VALIDATION", "Medium", "Endpoint appears to produce or consume object identifiers.", ["Use two owned accounts only.", "Confirm object ownership enforcement."], ["producer endpoint", "consumer endpoint", "private marker proof"]) for i in items[:30]]

    def _findings_from_state_actions(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("State-Changing Action Candidate", "Business Logic", i["endpoint"], "NEEDS_MANUAL_VALIDATION", "Medium", "Endpoint name suggests a state-changing operation.", ["Validate role and object ownership manually.", "Do not automate repeated requests against production."], ["normal workflow baseline", "authorized manual validation", "impact proof"]) for i in items[:30]]

    def _findings_from_graphql(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("GraphQL/API Review Candidate", "GraphQL/API", str(i), "NEEDS_MANUAL_VALIDATION", "Medium", "GraphQL operation or object ID signal detected.", ["Review operation authorization with owned accounts.", "Classify query vs mutation."], ["operation name", "object identifier", "auth boundary evidence"]) for i in items[:30]]

    def _findings_from_openapi(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("OpenAPI Route Review Candidate", "OpenAPI", f"{i['method']} {i['path']}", "NEEDS_MANUAL_VALIDATION", "High", "OpenAPI route was parsed and risk-classified.", ["Compare documented auth with observed behavior."], ["spec route", "auth expectation", "manual validation evidence"]) for i in items[:50]]

    def _findings_from_jwt(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("JWT / Session Posture Observation", "Session", str(i), "CONFIRMED_OBSERVATION", "High", "Session-related data was parsed locally for posture review.", ["Do not brute force or tamper with tokens.", "Review expiry, role claims, audience, issuer, and cookie flags."], ["redacted token metadata", "session impact if any"]) for i in items[:20]]

    def _findings_from_cloud(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("Cloud Exposure Review Candidate", "Cloud", i["signal"], "DISCOVERED", "Medium", "Cloud/CDN/storage/config reference detected.", ["Confirm public vs intended exposure only.", "Do not access private resources."], ["exposure location", "sensitivity proof", "access context"]) for i in items[:30]]

    def _findings_from_cache(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("Cache Behavior Review Candidate", "Cache", str(i), i.get("status", "DISCOVERED"), "Medium", "Cache-related behavior needs context before reportability.", ["Check only owned authenticated data.", "Prove private marker is cacheable before escalating."], ["private marker", "cache headers", "reproducible cache behavior"]) for i in items[:20]]

    def _findings_from_mobile(self, items: list[dict[str, Any]]) -> list[UpliftFinding]:
        return [UpliftFinding("Mobile/API Recon Candidate", "Mobile API", i["endpoint"], "DISCOVERED", "Medium", "Endpoint came from mobile/API collection style input.", ["Map auth requirements.", "Compare mobile-only route behavior with web route behavior."], ["source collection", "endpoint purpose", "authorization evidence"]) for i in items[:30]]

    def _report_quality_gate(self, findings: list[UpliftFinding]) -> dict[str, Any]:
        blocked = [{"title": f.title, "reason": "Not enough proof for final report. Manual evidence required."} for f in findings if f.status in {"DISCOVERED", "CONFIRMED_OBSERVATION", "NEEDS_MANUAL_VALIDATION"}]
        return {"report_ready": [], "blocked_or_needs_validation": blocked[:50], "rule": "No evidence = no confirmed vulnerability"}

    def _defensive_exports(self, findings: list[UpliftFinding]) -> dict[str, str]:
        spl = []
        sigma = []
        for f in findings[:20]:
            keyword = re.sub(r"[^A-Za-z0-9_/-]", " ", f.signal)[:60].strip()
            if keyword:
                spl.append(f'index=web sourcetype=http "{keyword}" | stats count by uri, status, user')
                sigma.append(f"- title: Review {f.title}\n  status: experimental\n  logsource:\n    category: webserver\n  detection:\n    selection:\n      request|contains: '{keyword}'\n    condition: selection")
        return {"splunk_spl": "\n".join(spl), "sigma_style_rules": "\n\n".join(sigma)}


def analyze_uplift_text(text: str, output_dir: str = "reports/output/uplift") -> UpliftResult:
    result = UpliftModules().analyze(text)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "uplift-evidence.json").write_text(json.dumps(_to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "uplift-report.md").write_text(_markdown(result), encoding="utf-8")
    (out / "defensive-exports.txt").write_text(result.defensive_exports.get("splunk_spl", "") + "\n\n" + result.defensive_exports.get("sigma_style_rules", ""), encoding="utf-8")
    return result


def _to_dict(result: UpliftResult) -> dict[str, Any]:
    return {"imports": result.imports, "object_flows": result.object_flows, "state_actions": result.state_actions, "graphql": result.graphql, "openapi": result.openapi, "jwt_session": result.jwt_session, "cloud": result.cloud, "cache": result.cache, "mobile_api": result.mobile_api, "quality_gate": result.quality_gate, "defensive_exports": result.defensive_exports, "findings": [asdict(f) for f in result.findings]}


def _markdown(result: UpliftResult) -> str:
    lines = ["# VulnScope Uplift Module Report", "", "## Summary", ""]
    metrics = {"endpoints": len(result.imports.get("endpoints", [])), "object flow candidates": len(result.object_flows), "state-changing actions": len(result.state_actions), "GraphQL/API signals": len(result.graphql), "OpenAPI routes": len(result.openapi), "JWT/session observations": len(result.jwt_session), "cloud signals": len(result.cloud), "cache signals": len(result.cache), "mobile/API signals": len(result.mobile_api), "findings": len(result.findings)}
    lines += [f"- **{k}:** {v}" for k, v in metrics.items()]
    lines += ["", "## Findings", ""]
    for idx, f in enumerate(result.findings, start=1):
        lines += [f"### UPLIFT-{idx:03d} - {f.title}", f"- Category: {f.category}", f"- Status: {f.status}", f"- Confidence: {f.confidence}", f"- Signal: `{f.signal}`", f"- Reason: {f.reason}", "- Safe next steps:"]
        lines += [f"  - {s}" for s in f.safe_next_steps]
        lines += ["- Evidence required:"]
        lines += [f"  - {e}" for e in f.evidence_required]
        lines.append("")
    lines += ["## Report Quality Gate", "", f"Rule: {result.quality_gate.get('rule')}", f"Report-ready items: {len(result.quality_gate.get('report_ready', []))}", f"Needs validation: {len(result.quality_gate.get('blocked_or_needs_validation', []))}"]
    return "\n".join(lines)
