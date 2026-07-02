#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
JSON_LIKE_RE = re.compile(r"^\s*[\[{]")
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token"}
SAFE_HEADER_NAMES = {"x-forwarded-for", "x-real-ip", "referer", "user-agent", "accept-language"}
URL_PARAM_HINTS = {"url", "uri", "redirect", "redirect_uri", "next", "return", "return_url", "continue", "dest", "destination", "callback", "callback_url"}
OBJECT_PARAM_HINTS = {"id", "uid", "user", "user_id", "account", "account_id", "order", "order_id", "vehicle", "vin", "dealer", "dealerid", "dealer_id"}
SEARCH_PARAM_HINTS = {"q", "s", "search", "query", "keyword", "term", "filter"}
FILE_PARAM_HINTS = {"file", "path", "page", "template", "download", "document", "doc", "include"}


@dataclass
class ParameterRecord:
    url: str
    path: str
    method: str
    parameter: str
    original_value: str = ""
    source: str = "query"
    location: str = "query"
    data_type: str = "string"
    kind: str = "generic"
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_template: Any = None
    safe_to_test: bool = True
    reason: str = "safe GET query parameter"

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.url}::{self.location}::{self.parameter}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FormRecord:
    page_url: str
    action_url: str
    method: str
    enctype: str
    fields: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def redact(value: Any, limit: int = 300) -> str:
    text = str(value if value is not None else "")
    text = re.sub(r"(?i)(authorization|cookie|token|secret|password|passwd|api[_-]?key)(\s*[:=]\s*)([^\s;,]+)", r"\1\2<redacted>", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def normalize_url(raw: str, base: str | None = None) -> str:
    raw = str(raw or "").strip()
    if base:
        raw = urljoin(base, raw)
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    query = urlencode(parse_qs(parsed.query, keep_blank_values=True), doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def classify_value(value: Any) -> str:
    if value is None:
        return "null"
    text = str(value)
    if text == "":
        return "empty"
    if UUID_RE.match(text):
        return "uuid"
    if re.fullmatch(r"-?\d+", text):
        return "integer"
    if re.fullmatch(r"-?\d+\.\d+", text):
        return "float"
    if text.lower() in {"true", "false", "yes", "no", "on", "off"}:
        return "boolean"
    if JSON_LIKE_RE.match(text):
        return "json-string"
    if re.match(r"https?://", text, re.I):
        return "url"
    return "string"


def classify_kind(name: str, value: Any = "") -> str:
    low = name.lower().strip()
    dtype = classify_value(value)
    if low in URL_PARAM_HINTS or low.endswith("url") or "callback" in low:
        return "route-like"
    if low in FILE_PARAM_HINTS or low.endswith("file") or low.endswith("path"):
        return "resource-like"
    if low in OBJECT_PARAM_HINTS or low.endswith("_id") or dtype in {"integer", "uuid"}:
        return "object-like"
    if low in SEARCH_PARAM_HINTS:
        return "search-like"
    if any(word in low for word in ["sort", "filter", "page", "limit", "locale", "lang", "zip", "postal"]):
        return "state-like"
    return "generic"


def is_safe_get_parameter(method: str, location: str, name: str, url: str) -> tuple[bool, str]:
    method = method.upper()
    if method != "GET":
        return False, "non-GET inputs are inventoried only unless explicit lab policy is implemented"
    if location != "query":
        return False, "only query parameters are safe-active tested by default"
    path = (urlparse(url).path or "").lower()
    if any(part in path for part in ["login", "logout", "checkout", "payment", "delete", "upload", "password"]):
        return False, "sensitive workflow path skipped"
    if name.lower() in {"csrf", "csrf_token", "auth", "token", "session", "password", "pass"}:
        return False, "sensitive parameter name skipped"
    return True, "safe GET query parameter"


def _make_record(url: str, method: str, name: str, value: Any, source: str, location: str, *, content_type: str = "", headers: dict[str, str] | None = None, body_template: Any = None) -> ParameterRecord:
    url = normalize_url(url)
    safe, reason = is_safe_get_parameter(method, location, name, url)
    return ParameterRecord(
        url=url,
        path=urlparse(url).path or "/",
        method=method.upper(),
        parameter=name,
        original_value=redact(value, 500),
        source=source,
        location=location,
        data_type=classify_value(value),
        kind=classify_kind(name, value),
        content_type=content_type,
        headers={k: redact(v, 200) for k, v in (headers or {}).items() if k.lower() not in SENSITIVE_HEADER_NAMES},
        body_template=body_template,
        safe_to_test=safe,
        reason=reason,
    )


def flatten_json(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    output: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            output.extend(flatten_json(item, name))
    elif isinstance(value, list):
        for idx, item in enumerate(value[:20]):
            name = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            output.extend(flatten_json(item, name))
    else:
        output.append((prefix or "value", value))
    return output


def extract_from_url(url: str, *, source: str = "url", method: str = "GET") -> list[ParameterRecord]:
    url = normalize_url(url)
    parsed = urlparse(url)
    records: list[ParameterRecord] = []
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        for raw in values or [""]:
            records.append(_make_record(url, method, name, raw, source, "query"))
            if JSON_LIKE_RE.match(str(raw)):
                try:
                    parsed_json = json.loads(raw)
                    for nested_name, nested_value in flatten_json(parsed_json, name):
                        records.append(_make_record(url, method, nested_name, nested_value, source + ":nested-json-query", "query"))
                except Exception:
                    pass
    return records


def extract_from_form(form: FormRecord, *, source: str = "form") -> list[ParameterRecord]:
    method = form.method.upper() or "GET"
    records: list[ParameterRecord] = []
    action_url = normalize_url(form.action_url, form.page_url)
    if method == "GET":
        parsed = urlparse(action_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for name, value in form.fields.items():
            query.setdefault(name, [value])
        action_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))
    for name, value in form.fields.items():
        location = "query" if method == "GET" else "form-body"
        records.append(_make_record(action_url, method, name, value, source, location, content_type=form.enctype, body_template=dict(form.fields)))
    return records


def extract_from_json_body(url: str, method: str, body: str | bytes | None, *, source: str = "json-body", headers: dict[str, str] | None = None) -> list[ParameterRecord]:
    if body is None:
        return []
    raw = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else str(body)
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    return [_make_record(url, method, name, value, source, "json-body", content_type="application/json", headers=headers, body_template=parsed) for name, value in flatten_json(parsed)]


def extract_from_form_body(url: str, method: str, body: str | bytes | None, *, source: str = "form-body", headers: dict[str, str] | None = None) -> list[ParameterRecord]:
    if body is None:
        return []
    raw = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else str(body)
    parsed = parse_qs(raw, keep_blank_values=True)
    return [_make_record(url, method, name, values[0] if values else "", source, "form-body", content_type="application/x-www-form-urlencoded", headers=headers, body_template=raw) for name, values in parsed.items()]


def extract_from_headers(url: str, method: str, headers: dict[str, str] | None, *, source: str = "headers") -> list[ParameterRecord]:
    records: list[ParameterRecord] = []
    for name, value in (headers or {}).items():
        low = name.lower()
        if low in SENSITIVE_HEADER_NAMES:
            records.append(_make_record(url, method, name, "<redacted>", source, "header", headers=headers))
            records[-1].safe_to_test = False
            records[-1].reason = "sensitive header inventoried only"
        elif low in SAFE_HEADER_NAMES:
            records.append(_make_record(url, method, name, value, source, "header", headers=headers))
            records[-1].safe_to_test = False
            records[-1].reason = "header inventoried only; header mutation disabled by default"
    return records


def extract_from_cookies(url: str, cookies: dict[str, str] | None, *, source: str = "cookies") -> list[ParameterRecord]:
    records: list[ParameterRecord] = []
    for name, value in (cookies or {}).items():
        rec = _make_record(url, "GET", name, value, source, "cookie")
        rec.safe_to_test = False
        rec.reason = "cookie inventoried only; cookie mutation disabled by default"
        records.append(rec)
    return records


def extract_from_network_request(request: dict[str, Any]) -> list[ParameterRecord]:
    url = normalize_url(str(request.get("url") or ""))
    method = str(request.get("method") or "GET").upper()
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    post_data = request.get("post_data") or request.get("postData") or ""
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = str(v)
    records = extract_from_url(url, source=str(request.get("source") or "network-query"), method=method)
    records.extend(extract_from_headers(url, method, headers, source="network-headers"))
    if method in {"POST", "PUT", "PATCH"} and post_data:
        if "json" in content_type.lower() or JSON_LIKE_RE.match(str(post_data)):
            records.extend(extract_from_json_body(url, method, post_data, source="network-json-body", headers=headers))
        elif "x-www-form-urlencoded" in content_type.lower() or "=" in str(post_data):
            records.extend(extract_from_form_body(url, method, post_data, source="network-form-body", headers=headers))
    return records


def dedupe_parameters(records: list[ParameterRecord]) -> list[ParameterRecord]:
    seen: dict[str, ParameterRecord] = {}
    for rec in records:
        key = rec.key
        if key not in seen:
            seen[key] = rec
        else:
            prev = seen[key]
            prev.source = prev.source if rec.source in prev.source else prev.source + "+" + rec.source
            prev.safe_to_test = prev.safe_to_test or rec.safe_to_test
            if not prev.reason or prev.reason.startswith("non-"):
                prev.reason = rec.reason
    return list(seen.values())


def replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if parameter not in query and "." in parameter:
        parameter = parameter.split(".", 1)[0]
    query[parameter] = [value]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))


def summarize(records: list[ParameterRecord]) -> dict[str, int]:
    return {
        "total": len(records),
        "safe_to_test": sum(1 for r in records if r.safe_to_test),
        "query": sum(1 for r in records if r.location == "query"),
        "forms": sum(1 for r in records if r.location in {"form-body", "query"} and "form" in r.source),
        "json_body": sum(1 for r in records if r.location == "json-body"),
        "headers": sum(1 for r in records if r.location == "header"),
        "cookies": sum(1 for r in records if r.location == "cookie"),
    }
