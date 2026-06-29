from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

OUT_DIR = Path("reports/output/category-suite")
ID_PARAM_RE = re.compile(r"(^|_|-)(id|user|account|order|invoice|profile|uid|uuid|customer|member|org|tenant|file|doc|document|payment|transaction)(_|-|$)", re.I)
INT_LIKE_RE = re.compile(r"^\d{2,}$")
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.I)
DOM_SINK_RE = re.compile(r"(innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|setTimeout\(|setInterval\(|location\.hash|location\.search|new\s+Function)", re.I)
XSS_PARAM_RE = re.compile(r"(^|_|-)(q|query|search|s|keyword|term|message|msg|comment|content|html|text|title|name|callback|return|next)(_|-|$)", re.I)
INPUT_PATHS = ["reports/output/evidence.json", "reports/output/recon/domain-expansion.json", "reports/output/imports/har-import.json", "reports/output/safe-discovery/safe-discovery.json", "reports/output/auth/account-comparison.json", "reports/output/arsenal/katana-urls.txt", "reports/output/arsenal/gau-urls.txt", "reports/output/arsenal/waybackurls.txt", "reports/output/arsenal/arjun.txt", "reports/output/arsenal/httpx.txt"]

@dataclass
class CategoryToolResult:
    tool: str
    category: str
    status: str
    candidates: int
    notes: list[str]

@dataclass
class CategoryCandidate:
    title: str
    category: str
    url: str
    evidence: list[str]
    severity: str = "info"
    confidence: float = 0.0
    source: str = "category_suite"
    detector: str = "unknown"
    exploit_status: str = "not_exploited"
    validation_status: str = "review_candidate"
    impact: str = "Requires manual validation on owned or explicitly authorized assets."
    remediation: str = "Review the affected endpoint and enforce contextual server-side controls."
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class CategoryReviewSuite:
    """Evidence-only category review. No payload injection, ID brute force, or state change."""
    def __init__(self, target: str | None = None) -> None:
        self.target = target or "authorized-target"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.inputs = self._load_inputs()
        self.urls = sorted(self._extract_urls(self.inputs))
        self.js_texts = self._extract_text_blobs(self.inputs)

    def run(self) -> dict[str, Any]:
        started = time.time()
        candidates: list[CategoryCandidate] = []
        tool_results: list[CategoryToolResult] = []
        detectors = [self._xss_reflection_surface_mapper, self._xss_dom_sink_mapper, self._xss_js_route_mapper, self._xss_callback_param_mapper, self._xss_upload_html_context_mapper, self._xss_header_posture_correlator, self._idor_object_param_mapper, self._idor_account_comparison_reviewer, self._idor_multi_tenant_route_mapper, self._idor_file_document_route_mapper, self._idor_state_changing_endpoint_mapper, self._idor_numeric_identifier_clusterer]
        for detector in detectors:
            before = len(candidates)
            name = detector.__name__.lstrip("_")
            category = "xss" if name.startswith("xss") else "idor"
            try:
                produced = detector()
                candidates.extend(produced)
                tool_results.append(CategoryToolResult(name, category, "ok", len(candidates) - before, [f"produced {len(produced)} candidates"]))
            except Exception as exc:
                tool_results.append(CategoryToolResult(name, category, "error", 0, [str(exc)]))
        deduped = self._dedupe(candidates)
        payload = {"target": self.target, "mode": "safe_category_review", "started_at": started, "ended_at": time.time(), "rules": {"exploit_execution": False, "payload_injection": False, "idor_bruteforce": False, "credential_collection": False, "state_change": False}, "tool_count_by_category": {"xss": 6, "idor": 6}, "tool_results": [asdict(t) for t in tool_results], "candidates": [c.to_dict() for c in deduped], "summary": {"input_urls": len(self.urls), "candidates": len(deduped), "xss_candidates": len([c for c in deduped if c.category.startswith("xss")]), "idor_candidates": len([c for c in deduped if c.category.startswith("idor")])}}
        (OUT_DIR / "category-suite.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUT_DIR / "category-suite.md").write_text(self._markdown(payload), encoding="utf-8")
        return payload

    def _load_inputs(self) -> dict[str, Any]:
        loaded: dict[str, Any] = {}
        for raw in INPUT_PATHS:
            path = Path(raw)
            if not path.exists():
                continue
            try:
                loaded[raw] = json.loads(path.read_text(encoding="utf-8", errors="ignore")) if path.suffix == ".json" else path.read_text(encoding="utf-8", errors="ignore")
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
                if isinstance(value.get(key), str) and value[key].startswith(("http://", "https://")):
                    urls.add(value[key])
            for item in value.values():
                urls.update(self._extract_urls(item))
        return urls

    def _extract_text_blobs(self, value: Any) -> list[str]:
        blobs: list[str] = []
        if isinstance(value, str):
            if any(token in value for token in ["innerHTML", "location", "function", "script", "endpoint"]):
                blobs.append(value[:100000])
        elif isinstance(value, list):
            for item in value:
                blobs.extend(self._extract_text_blobs(item))
        elif isinstance(value, dict):
            for key in ["body_preview", "content", "script", "source", "output_tail"]:
                if isinstance(value.get(key), str):
                    blobs.append(value[key][:100000])
            for item in value.values():
                blobs.extend(self._extract_text_blobs(item))
        return blobs

    def _params(self, url: str) -> list[tuple[str, str]]:
        return parse_qsl(urlparse(url).query, keep_blank_values=True)

    def _xss_reflection_surface_mapper(self) -> list[CategoryCandidate]:
        return [CategoryCandidate("XSS reflection-prone parameter surface", "xss_surface", url, ["url_parameter_name"], "info", 0.58, detector="xss_reflection_surface_mapper", remediation="Server-side encode output by context and validate where the parameter is rendered.") for url in self.urls if any(XSS_PARAM_RE.search(p) for p, _ in self._params(url))]

    def _xss_dom_sink_mapper(self) -> list[CategoryCandidate]:
        return [CategoryCandidate("DOM sink pattern requires client-side review", "xss_dom", self.target, [f"text_blob:{idx}"], "low", 0.64, detector="xss_dom_sink_mapper", impact="A dangerous DOM sink was observed in collected client-side evidence. Confirm source-to-sink flow manually.", remediation="Prefer safe DOM APIs, sanitize untrusted data, and avoid HTML-writing sinks.") for idx, blob in enumerate(self.js_texts) if DOM_SINK_RE.search(blob)][:25]

    def _xss_js_route_mapper(self) -> list[CategoryCandidate]:
        return [CategoryCandidate("JavaScript asset queued for endpoint and sink review", "xss_js_review", url, ["javascript_asset"], "info", 0.45, detector="xss_js_route_mapper", remediation="Review JS asset for unsafe rendering, route parameters, and client-side trust boundaries.") for url in self.urls if ".js" in urlparse(url).path.lower()][:50]

    def _xss_callback_param_mapper(self) -> list[CategoryCandidate]:
        return [CategoryCandidate("JSONP/callback parameter requires script-context review", "xss_script_context", url, ["callback_parameter"], "low", 0.66, detector="xss_callback_param_mapper", remediation="Avoid JSONP where possible; validate callback names and return JSON with strict content type.") for url in self.urls if any(p.lower() in {"callback", "jsonp", "cb"} for p, _ in self._params(url))]

    def _xss_upload_html_context_mapper(self) -> list[CategoryCandidate]:
        tokens = ["upload", "profile", "comment", "review", "message", "feedback", "wysiwyg"]
        return [CategoryCandidate("User-content route requires stored-XSS review", "xss_stored_surface", url, ["route_name"], "info", 0.54, detector="xss_upload_html_context_mapper", remediation="Ensure stored user content is encoded by output context and sanitized when HTML is intentionally allowed.") for url in self.urls if any(t in urlparse(url).path.lower() for t in tokens)]

    def _xss_header_posture_correlator(self) -> list[CategoryCandidate]:
        safe = self.inputs.get("reports/output/safe-discovery/safe-discovery.json", {})
        titles = " ".join(f.get("title", "") for f in safe.get("findings", []) if isinstance(f, dict)) if isinstance(safe, dict) else ""
        return [CategoryCandidate("Missing CSP increases XSS blast-radius if a sink is confirmed", "xss_hardening", self.target, ["safe_discovery"], "info", 0.50, detector="xss_header_posture_correlator", impact="Not a standalone vulnerability. Use as context when a real XSS sink/source flow is validated.", remediation="Add a tested Content-Security-Policy, preferably report-only first.")] if "Content-Security-Policy" in titles else []

    def _idor_object_param_mapper(self) -> list[CategoryCandidate]:
        return [CategoryCandidate("Object identifier parameter requires authorization review", "idor_parameter", url, ["object_identifier_parameter"], "medium", 0.70, detector="idor_object_param_mapper", remediation="Enforce object-level authorization server-side for every object lookup or mutation.") for url in self.urls if any(ID_PARAM_RE.search(p) or UUID_RE.search(v) for p, v in self._params(url))]

    def _idor_account_comparison_reviewer(self) -> list[CategoryCandidate]:
        p = Path("reports/output/auth/account-comparison.json")
        if not p.exists():
            return []
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []
        return [CategoryCandidate("Account A/B comparison contains authorization review items", "idor_account_comparison", self.target, [str(p)], "medium", 0.74, detector="idor_account_comparison_reviewer", remediation="Manually validate whether each cross-account difference is expected and authorized.")] if isinstance(data, dict) and len(data.get("differences", [])) else []

    def _idor_multi_tenant_route_mapper(self) -> list[CategoryCandidate]:
        tokens = ["tenant", "org", "organization", "workspace", "team", "company"]
        return [CategoryCandidate("Multi-tenant route requires tenant isolation review", "idor_tenant_isolation", url, ["tenant_route"], "medium", 0.68, detector="idor_multi_tenant_route_mapper", remediation="Verify every tenant/workspace route enforces membership and role checks server-side.") for url in self.urls if any(t in urlparse(url).path.lower() for t in tokens)]

    def _idor_file_document_route_mapper(self) -> list[CategoryCandidate]:
        tokens = ["file", "download", "document", "invoice", "receipt", "export", "attachment"]
        return [CategoryCandidate("File/document route requires object access review", "idor_file_access", url, ["file_or_document_route"], "medium", 0.69, detector="idor_file_document_route_mapper", remediation="Authorize each file/document request against the requesting user and avoid predictable public identifiers.") for url in self.urls if any(t in urlparse(url).path.lower() for t in tokens)]

    def _idor_state_changing_endpoint_mapper(self) -> list[CategoryCandidate]:
        tokens = ["update", "edit", "delete", "remove", "create", "transfer", "payment", "admin"]
        return [CategoryCandidate("State-changing route requires role and object authorization review", "idor_state_change", url, ["state_changing_route_name"], "medium", 0.67, detector="idor_state_changing_endpoint_mapper", remediation="Apply authorization checks before every state change and add audit logging for sensitive actions.") for url in self.urls if any(t in urlparse(url).path.lower() for t in tokens)]

    def _idor_numeric_identifier_clusterer(self) -> list[CategoryCandidate]:
        clusters: dict[str, int] = {}
        example: dict[str, str] = {}
        for url in self.urls:
            for param, value in self._params(url):
                if ID_PARAM_RE.search(param) and INT_LIKE_RE.search(value):
                    clusters[param] = clusters.get(param, 0) + 1
                    example.setdefault(param, url)
        return [CategoryCandidate(f"Repeated numeric object identifier `{param}` requires IDOR review", "idor_predictable_identifier", example[param], ["numeric_identifier_cluster"], "medium", 0.72, detector="idor_numeric_identifier_clusterer", remediation="Prefer non-enumerable identifiers where appropriate and enforce authorization independent of identifier complexity.") for param, count in clusters.items() if count >= 2]

    def _dedupe(self, candidates: list[CategoryCandidate]) -> list[CategoryCandidate]:
        seen: dict[tuple[str, str, str], CategoryCandidate] = {}
        for c in candidates:
            key = (c.title, c.category, c.url)
            if key not in seen or c.confidence > seen[key].confidence:
                seen[key] = c
        return sorted(seen.values(), key=lambda c: c.confidence, reverse=True)

    def _markdown(self, payload: dict[str, Any]) -> str:
        lines = [f"# VulnScope Category Review Suite — {payload['target']}", "", "Evidence-only review candidates. No exploitation or payload injection performed.", "", "## Tool Coverage"]
        for result in payload["tool_results"]:
            lines.append(f"- `{result['tool']}` [{result['category']}] — {result['status']} — candidates: `{result['candidates']}`")
        lines += ["", "## Candidates"]
        for item in payload["candidates"][:80]:
            lines += [f"### {item['title']}", f"- Category: `{item['category']}`", f"- Detector: `{item['detector']}`", f"- URL: `{item['url']}`", f"- Confidence: `{item['confidence']}`", f"- Status: `{item['validation_status']}` / `{item['exploit_status']}`", ""]
        if not payload["candidates"]:
            lines.append("No category-specific review candidates found from available evidence.")
        return "\n".join(lines)

def run_category_suite(target: str | None = None) -> dict[str, Any]:
    return CategoryReviewSuite(target=target).run()
