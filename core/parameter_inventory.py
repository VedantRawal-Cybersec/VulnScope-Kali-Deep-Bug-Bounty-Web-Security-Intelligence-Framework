#!/usr/bin/env python3
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.scan_state import ParamRecord, ScanState

ROUTE_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "return_url", "continue", "dest", "destination", "callback"}
REFERENCE_PARAMS = ROUTE_PARAMS | {"uri", "link", "target", "site", "host", "domain", "endpoint", "callback_url"}
RESOURCE_PARAMS = {"file", "path", "page", "template", "folder", "dir", "download", "document", "doc", "include"}
OBJECT_PARAMS = {"id", "uid", "user", "user_id", "account", "account_id", "order", "order_id", "invoice", "invoice_id", "profile_id"}
SEARCH_PARAMS = {"q", "query", "search", "keyword", "term", "s"}


def param_kind(name: str) -> str:
    value = name.lower().strip()
    if value in ROUTE_PARAMS:
        return "route-like"
    if value in REFERENCE_PARAMS or value.endswith("url") or "callback" in value:
        return "reference-like"
    if value in RESOURCE_PARAMS or value.endswith("file") or value.endswith("path"):
        return "resource-like"
    if value in OBJECT_PARAMS or value.endswith("_id") or value == "id":
        return "object-like"
    if value in SEARCH_PARAMS:
        return "search-like"
    if any(x in value for x in ["lang", "locale", "theme", "sort", "filter", "page", "limit"]):
        return "state-like"
    return "generic"


def risk_score(name: str, kind: str, url: str) -> int:
    score = {"route-like": 80, "reference-like": 75, "resource-like": 70, "object-like": 65, "search-like": 55, "state-like": 35, "generic": 25}.get(kind, 20)
    path = (urlparse(url).path or "").lower()
    if re.search(r"/api/|/graphql|/json|/rest", path):
        score += 10
    if re.search(r"account|order|invoice|user|profile", path):
        score += 10
    if len(name) <= 2:
        score += 3
    return min(100, score)


def replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))


def add_params_from_url(state: ScanState, url: str, source: str) -> int:
    count = 0
    query = parse_qs(urlparse(url).query, keep_blank_values=True)
    for name, values in query.items():
        kind = param_kind(name)
        record = ParamRecord(url=url, name=name, value=values[0] if values else "", source=source, kind=kind, risk_score=risk_score(name, kind, url))
        before = len(state.params)
        state.add_param(record)
        count += 1 if len(state.params) > before else 0
    return count


def add_get_form_params(state: ScanState, action_url: str, params: dict[str, str], source: str = "get-form") -> int:
    parsed = urlparse(action_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for name, value in params.items():
        query.setdefault(name, [value])
    form_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))
    count = 0
    for name, value in params.items():
        kind = param_kind(name)
        record = ParamRecord(url=form_url, name=name, value=value, source=source, kind=kind, risk_score=risk_score(name, kind, form_url))
        before = len(state.params)
        state.add_param(record)
        count += 1 if len(state.params) > before else 0
    return count


def cluster_key(url: str, param: str) -> str:
    parsed = urlparse(url)
    path = re.sub(r"/\d+", "/{n}", parsed.path or "/")
    path = re.sub(r"/[a-f0-9]{8,}", "/{hex}", path, flags=re.I)
    return f"{parsed.netloc}:{path}:{param}"


def dedupe_by_cluster(params: list[ParamRecord], max_per_cluster: int = 3) -> list[ParamRecord]:
    seen: dict[str, int] = {}
    output: list[ParamRecord] = []
    for item in sorted(params, key=lambda p: p.risk_score, reverse=True):
        key = cluster_key(item.url, item.name)
        if seen.get(key, 0) >= max_per_cluster:
            continue
        seen[key] = seen.get(key, 0) + 1
        output.append(item)
    return output
