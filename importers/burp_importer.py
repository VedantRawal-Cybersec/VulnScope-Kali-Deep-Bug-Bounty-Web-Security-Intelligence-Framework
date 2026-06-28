from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
SENSITIVE_QUERY_KEYS = {"token", "api_key", "apikey", "key", "secret", "password", "session"}


@dataclass
class BurpEndpoint:
    method: str
    url: str
    host: str
    path: str
    status: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    query_keys: list[str]
    risk_signals: list[str]
    source: str = "burp"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decode_text(value: str | None, is_base64: bool = False) -> str:
    if not value:
        return ""
    if is_base64:
        try:
            return base64.b64decode(value).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return value


def _parse_headers(raw: str) -> tuple[str, dict[str, str]]:
    lines = raw.replace("\r\n", "\n").split("\n")
    first = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        headers[key] = "<REDACTED>" if key in SENSITIVE_HEADERS else v.strip()[:300]
    return first, headers


def _signals(method: str, path: str, query_keys: list[str], status: int) -> list[str]:
    low = path.lower()
    signals: list[str] = []
    if any(x in low for x in ["api", "graphql", "v1", "v2"]):
        signals.append("api_surface")
    if any(x in low for x in ["login", "oauth", "session", "auth", "sso"]):
        signals.append("auth_flow")
    if any(k.lower() in SENSITIVE_QUERY_KEYS for k in query_keys):
        signals.append("sensitive_query_key_redacted")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        signals.append("state_changing_method_review")
    if status in {401, 403}:
        signals.append("authorization_boundary")
    return signals


def import_burp_xml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    root = ET.fromstring(p.read_text(encoding="utf-8", errors="ignore"))
    endpoints: list[BurpEndpoint] = []
    for item in root.findall(".//item"):
        url = item.findtext("url") or ""
        method = (item.findtext("method") or "GET").upper()
        status = int(item.findtext("status") or 0)
        request_el = item.find("request")
        response_el = item.find("response")
        request_raw = _decode_text(request_el.text if request_el is not None else "", (request_el.get("base64") == "true") if request_el is not None else False)
        response_raw = _decode_text(response_el.text if response_el is not None else "", (response_el.get("base64") == "true") if response_el is not None else False)
        _, req_headers = _parse_headers(request_raw)
        _, res_headers = _parse_headers(response_raw)
        parsed = urlparse(url)
        q_keys = sorted(parse_qs(parsed.query).keys())
        safe_q_keys = ["<REDACTED>" if k.lower() in SENSITIVE_QUERY_KEYS else k for k in q_keys]
        endpoints.append(BurpEndpoint(method=method, url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}", host=(parsed.hostname or "").lower(), path=parsed.path or "/", status=status, request_headers=req_headers, response_headers=res_headers, query_keys=safe_q_keys, risk_signals=_signals(method, parsed.path, q_keys, status)))
    return {"source": str(p), "type": "burp_xml", "count": len(endpoints), "endpoints": [e.to_dict() for e in endpoints], "summary": summarize(endpoints)}


def summarize(endpoints: list[BurpEndpoint]) -> dict[str, Any]:
    hosts = sorted({e.host for e in endpoints if e.host})
    methods: dict[str, int] = {}
    signals: dict[str, int] = {}
    for e in endpoints:
        methods[e.method] = methods.get(e.method, 0) + 1
        for signal in e.risk_signals:
            signals[signal] = signals.get(signal, 0) + 1
    return {"hosts": hosts, "methods": methods, "signals": signals}


def save_burp_import(path: str | Path, out_path: str | Path = "reports/output/imports/burp-import.json") -> Path:
    result = import_burp_xml(path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
