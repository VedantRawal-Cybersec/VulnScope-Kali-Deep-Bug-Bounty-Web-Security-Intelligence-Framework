from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

OUT = Path("reports/output/normalized")
SOURCES = [
    "reports/output/recon/domain-expansion.json",
    "reports/output/imports/har-import.json",
    "reports/output/safe-discovery/safe-discovery.json",
    "reports/output/category-suite/category-suite.json",
    "reports/output/comprehensive-suite/comprehensive-suite.json",
    "reports/output/auth/account-comparison.json",
    "reports/output/auth/google-context/google-context-review.json",
    "reports/output/arsenal/gau-urls.txt",
    "reports/output/arsenal/waybackurls.txt",
    "reports/output/arsenal/katana-urls.txt",
    "reports/output/arsenal/httpx.txt",
    "reports/output/mega-tools/mega-tools-status.json",
]

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)


def load_source(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        if p.suffix == ".json":
            return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return {"_load_error": str(exc), "_path": path}


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def extract_urls(value: Any) -> set[str]:
    urls: set[str] = set()
    if isinstance(value, str):
        for match in URL_RE.findall(value):
            urls.add(match.rstrip("),.;]"))
        for line in value.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.add(line)
    elif isinstance(value, dict):
        for key in ["url", "endpoint", "request_url", "target"]:
            v = value.get(key)
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                urls.add(v)
        for item in value.values():
            urls.update(extract_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.update(extract_urls(item))
    return urls


def endpoint_record(url: str, source: str = "unknown") -> dict[str, Any]:
    parsed = urlparse(url)
    params = sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    tags = []
    low = (parsed.path + "?" + parsed.query).lower()
    if any(x in low for x in ["id=", "user", "account", "order", "invoice", "uuid"]):
        tags.append("object_reference")
    if any(x in low for x in ["redirect", "return", "next", "continue", "url="]):
        tags.append("redirect_surface")
    if any(x in low for x in ["callback", "jsonp", "q=", "search", "comment"]):
        tags.append("rendering_surface")
    if any(x in low for x in ["api", "graphql", "v1", "v2"]):
        tags.append("api_surface")
    if any(x in low for x in ["upload", "file", "download", "export"]):
        tags.append("file_surface")
    return {
        "type": "endpoint",
        "url": url,
        "scheme": parsed.scheme,
        "host": parsed.netloc.split(":")[0].lower(),
        "path": parsed.path or "/",
        "params": params,
        "source": source,
        "risk_tags": sorted(set(tags)),
    }


def normalize_all(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    loaded = {src: load_source(src) for src in SOURCES}
    endpoints: dict[str, dict[str, Any]] = {}
    candidates = []
    for src, data in loaded.items():
        for url in extract_urls(data):
            endpoints[url] = endpoint_record(url, src)
        for obj in walk(data):
            if any(k in obj for k in ["title", "category", "detector", "severity", "confidence"]):
                item = dict(obj)
                item["source_file"] = src
                candidates.append(item)
    params = sorted({p for e in endpoints.values() for p in e.get("params", [])})
    hosts = sorted({e["host"] for e in endpoints.values() if e.get("host")})
    payload = {
        "target": target or "authorized-target",
        "generated_at": time.time(),
        "summary": {"hosts": len(hosts), "endpoints": len(endpoints), "parameters": len(params), "candidates": len(candidates)},
        "hosts": hosts,
        "parameters": params,
        "endpoints": sorted(endpoints.values(), key=lambda x: x["url"]),
        "candidates": candidates,
    }
    (OUT / "normalized-evidence.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Normalized Evidence — {payload['target']}", "", f"Hosts: `{len(hosts)}`", f"Endpoints: `{len(endpoints)}`", f"Parameters: `{len(params)}`", f"Candidates: `{len(candidates)}`", "", "## Top Endpoints"]
    for e in payload["endpoints"][:100]:
        lines.append(f"- `{e['url']}` tags=`{','.join(e['risk_tags'])}` params=`{','.join(e['params'])}`")
    (OUT / "normalized-evidence.md").write_text("\n".join(lines), encoding="utf-8")
    return payload
