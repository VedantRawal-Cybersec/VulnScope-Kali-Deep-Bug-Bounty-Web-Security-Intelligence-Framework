from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
SENSITIVE_QUERY_KEYS = {"token", "api_key", "apikey", "key", "secret", "password", "session"}


@dataclass
class TrafficEndpoint:
    method: str
    url: str
    host: str
    path: str
    status: int
    content_type: str
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    query_keys: list[str]
    risk_signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _headers_to_dict(headers: list[dict[str, Any]]) -> dict[str, str]:
    out = {}
    for h in headers or []:
        name = str(h.get("name", "")).lower()
        value = str(h.get("value", ""))
        out[name] = "<REDACTED>" if name in SENSITIVE_HEADERS else value[:300]
    return out


def import_har(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    entries = data.get("log", {}).get("entries", [])
    endpoints: list[TrafficEndpoint] = []
    for entry in entries:
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = req.get("url", "")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q_keys = sorted(q.keys())
        signals = []
        path_low = parsed.path.lower()
        if any(x in path_low for x in ["api", "graphql", "v1", "v2"]):
            signals.append("api_surface")
        if any(x in path_low for x in ["login", "oauth", "session", "auth", "sso"]):
            signals.append("auth_flow")
        if any(k.lower() in SENSITIVE_QUERY_KEYS for k in q_keys):
            signals.append("sensitive_query_key_redacted")
        if str(req.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            signals.append("state_changing_method_review")
        endpoints.append(TrafficEndpoint(
            method=str(req.get("method", "GET")).upper(),
            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            host=(parsed.hostname or "").lower(),
            path=parsed.path or "/",
            status=int(res.get("status", 0) or 0),
            content_type=str(res.get("content", {}).get("mimeType", "")),
            request_headers=_headers_to_dict(req.get("headers", [])),
            response_headers=_headers_to_dict(res.get("headers", [])),
            query_keys=["<REDACTED>" if k.lower() in SENSITIVE_QUERY_KEYS else k for k in q_keys],
            risk_signals=signals,
        ))
    return {
        "source": str(p),
        "count": len(endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
        "summary": summarize_endpoints(endpoints),
    }


def summarize_endpoints(endpoints: list[TrafficEndpoint]) -> dict[str, Any]:
    hosts = sorted({e.host for e in endpoints if e.host})
    methods = {}
    signals = {}
    for e in endpoints:
        methods[e.method] = methods.get(e.method, 0) + 1
        for signal in e.risk_signals:
            signals[signal] = signals.get(signal, 0) + 1
    return {"hosts": hosts, "methods": methods, "signals": signals}


def save_import(path: str | Path, out_path: str | Path = "reports/output/imports/har-import.json") -> Path:
    result = import_har(path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
