#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

COMMON_API_DOCS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/swagger.json",
    "/redoc",
    "/graphql",
]

API_HINT_RE = re.compile(r"/(?:api|graphql|v[0-9]+|rest|rpc|ajax)(?:/|\?|$)", re.I)


class APIDiscoveryEngine:
    """Safe API discovery for authorized websites.

    It imports API-like URLs from the current surface, checks common documentation
    paths with GET only, parses OpenAPI documents, and writes an API inventory.
    """

    def __init__(self, *, state: Any, client: Any, dashboard: Any | None = None, seed_urls: list[str] | None = None, max_docs: int = 40) -> None:
        self.state = state
        self.client = client
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.seed_urls = seed_urls or []
        self.max_docs = max(1, int(max_docs))
        self.endpoints: dict[str, dict[str, Any]] = {}
        self.docs: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str, url: str = "", evidence: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="API Discovery", phase_progress=58, current_agent="APIDiscoveryAgent", current_tool="api_discovery", action=action, endpoint=url or self.target, evidence=evidence[:1000], safety_status="GET-only API discovery • no mutation • no destructive methods")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def add_endpoint(self, url: str, *, source: str, method: str = "GET", params: list[str] | None = None, evidence: str = "") -> None:
        if not url:
            return
        key = method.upper() + " " + url
        item = self.endpoints.setdefault(key, {"method": method.upper(), "url": url, "sources": [], "params": [], "evidence": ""})
        if source not in item["sources"]:
            item["sources"].append(source)
        for param in params or []:
            if param not in item["params"]:
                item["params"].append(param)
        if evidence and not item.get("evidence"):
            item["evidence"] = evidence[:500]
        try:
            self.state.add_url(url, depth=1, source="api-discovery:" + source)
        except Exception:
            pass

    def from_state_urls(self) -> None:
        for record in getattr(self.state, "urls", {}).values():
            url = getattr(record, "url", "")
            path = urlparse(url).path or ""
            if API_HINT_RE.search(path):
                params = list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
                self.add_endpoint(url, source="state-url", params=params, evidence="API-like path discovered in surface map")

    def candidate_docs(self) -> list[str]:
        base = self.target.rstrip("/") + "/"
        rows = [urljoin(base, item.lstrip("/")) for item in COMMON_API_DOCS]
        rows.extend(self.seed_urls)
        return list(dict.fromkeys(rows))[: self.max_docs]

    def parse_openapi(self, url: str, payload: dict[str, Any]) -> None:
        paths = payload.get("paths") or {}
        servers = payload.get("servers") or []
        base = self.target
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict) and first.get("url"):
                base = urljoin(self.target, str(first.get("url")))
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, spec in methods.items():
                method_up = str(method).upper()
                if method_up not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                params: list[str] = []
                if isinstance(spec, dict):
                    for param in spec.get("parameters", []) or []:
                        if isinstance(param, dict) and param.get("name"):
                            params.append(str(param["name"]))
                full = urljoin(base.rstrip("/") + "/", str(path).lstrip("/"))
                if params and method_up == "GET":
                    parsed = urlparse(full)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    for param in params:
                        query.setdefault(param, ["test"])
                    full = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))
                self.add_endpoint(full, source="openapi", method=method_up, params=params, evidence=f"Imported from {url}")

    def probe_docs(self) -> None:
        for url in self.candidate_docs():
            self.dash("Checking API documentation path", url)
            try:
                res = self.client.get(url, purpose="api-doc-discovery")
            except Exception as exc:
                self.errors.append({"url": url, "error": str(exc)[:500]})
                continue
            if not getattr(res, "received", False):
                continue
            ctype = (res.headers.get("Content-Type", "") if getattr(res, "headers", None) else "").lower()
            body = res.text or ""
            doc = {"url": url, "status_code": res.status_code, "content_type": ctype, "looks_like_api_doc": False}
            if res.ok and ("openapi" in body[:2000].lower() or "swagger" in body[:2000].lower() or url.endswith(".json")):
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        doc["looks_like_api_doc"] = True
                        doc["title"] = ((parsed.get("info") or {}).get("title") or "")[:120]
                        self.parse_openapi(url, parsed)
                except Exception as exc:
                    doc["parse_error"] = str(exc)[:300]
            if "/graphql" in urlparse(url).path.lower() and res.status_code in {200, 400, 405}:
                self.add_endpoint(url, source="graphql-probe", method="POST", evidence=f"GraphQL-like endpoint returned HTTP {res.status_code} to GET probe")
                doc["looks_like_api_doc"] = True
                doc["type"] = "graphql-candidate"
            self.docs.append(doc)

    def write_reports(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "endpoints": list(self.endpoints.values()), "documents": self.docs, "errors": self.errors, "rules": "GET-only discovery. Non-GET methods are inventoried from documentation but not executed."}
        json_path = self.out_dir / "api-discovery.json"
        md_path = self.out_dir / "api-discovery.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# API Discovery Report", "", f"Target: `{self.target}`", "", "## Summary", f"- API endpoints inventoried: `{len(payload['endpoints'])}`", f"- API documentation candidates checked: `{len(self.docs)}`", f"- Errors: `{len(self.errors)}`", "", "## Endpoints", ""]
        if not payload["endpoints"]:
            lines.append("No API-like endpoints were discovered from safe GET-only discovery.")
        else:
            for item in payload["endpoints"][:300]:
                lines.append(f"- `{item['method']}` `{item['url']}` params=`{', '.join(item.get('params') or [])}` sources=`{', '.join(item.get('sources') or [])}`")
        lines.extend(["", "## Documentation Candidates", ""])
        for doc in self.docs[:100]:
            lines.append(f"- `{doc.get('url')}` status=`{doc.get('status_code')}` api_doc=`{doc.get('looks_like_api_doc')}` type=`{doc.get('type','')}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"api_discovery_json": str(json_path), "api_discovery_md": str(md_path)}

    def run(self) -> dict[str, Any]:
        self.dash("Starting API discovery")
        self.from_state_urls()
        self.probe_docs()
        reports = self.write_reports()
        try:
            self.state.stats["api_discovery_endpoints"] = len(self.endpoints)
            self.state.stats["api_discovery_docs"] = len(self.docs)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "endpoints": len(self.endpoints), "documents": len(self.docs), "errors": len(self.errors), "reports": reports}
