from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

OUT = Path("reports/output/aegis/google-intel")

SAFE_QUERIES = [
    "site:{domain}",
    "site:{domain} admin OR login OR dashboard",
    "site:{domain} filetype:pdf OR filetype:doc OR filetype:xls",
    "site:{domain} swagger OR openapi OR graphql",
    "site:{domain} backup OR old OR staging OR dev",
    "site:github.com {domain}",
]

SENSITIVE_WORDS = ["password", "secret", "token", "api_key", "apikey", "credential", "private_key"]


def redact(text: str) -> str:
    value = text or ""
    for word in SENSITIVE_WORDS:
        value = value.replace(word, word[:2] + "[redacted]")
        value = value.replace(word.upper(), word[:2].upper() + "[redacted]")
    return value


def custom_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_CUSTOM_SEARCH_API_KEY")
    cse_id = os.environ.get("GOOGLE_CSE_ID") or os.environ.get("GOOGLE_CUSTOM_SEARCH_ENGINE_ID")
    if not api_key or not cse_id:
        return []
    params = urlencode({"key": api_key, "cx": cse_id, "q": query, "num": min(limit, 10)})
    url = "https://www.googleapis.com/customsearch/v1?" + params
    req = Request(url, headers={"User-Agent": "VulnScope-AEGIS-SAFE/1.0"})
    with urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode("utf-8", errors="ignore"))
    items = []
    for item in data.get("items", []):
        items.append({
            "title": redact(str(item.get("title", ""))),
            "link": item.get("link"),
            "snippet": redact(str(item.get("snippet", ""))),
            "display_link": item.get("displayLink"),
        })
    return items


def run_google_intel(domain: str, limit_per_query: int = 5) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    configured = bool((os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_CUSTOM_SEARCH_API_KEY")) and (os.environ.get("GOOGLE_CSE_ID") or os.environ.get("GOOGLE_CUSTOM_SEARCH_ENGINE_ID")))
    for template in SAFE_QUERIES:
        query = template.format(domain=domain)
        try:
            hits = custom_search(query, limit=limit_per_query) if configured else []
        except Exception as exc:
            hits = [{"error": str(exc)}]
        results.append({"query": query, "hits": hits})
    candidates = []
    for block in results:
        for hit in block.get("hits", []):
            link = hit.get("link")
            if not link:
                continue
            low = (link + " " + str(hit.get("snippet", ""))).lower()
            tags = []
            if any(x in low for x in ["swagger", "openapi", "graphql"]):
                tags.append("api_surface_candidate")
            if any(x in low for x in ["admin", "dashboard", "login"]):
                tags.append("sensitive_route_candidate")
            if any(x in low for x in ["backup", "old", "staging", "dev"]):
                tags.append("environment_exposure_candidate")
            if "github.com" in low:
                tags.append("public_code_reference")
            if tags:
                candidates.append({"url": link, "title": hit.get("title"), "tags": tags, "source": "google_custom_search", "status": "review_candidate"})
    payload = {
        "domain": domain,
        "generated_at": time.time(),
        "configured": configured,
        "safe_mode": True,
        "summary": {"queries": len(results), "hits": sum(len(x.get("hits", [])) for x in results), "candidates": len(candidates)},
        "setup_note": "Set GOOGLE_API_KEY and GOOGLE_CSE_ID to enable Google Custom Search. Results are redacted and not fetched directly.",
        "queries": results,
        "candidates": candidates,
    }
    (OUT / "google-intel.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# AEGIS-SAFE Google Intelligence — {domain}", "", f"Configured: `{configured}`", f"Candidates: `{len(candidates)}`", "", "## Candidates"]
    for c in candidates[:100]:
        lines.append(f"- `{c['url']}` tags=`{','.join(c['tags'])}` title=`{c.get('title')}`")
    if not configured:
        lines += ["", "## Setup", "Set environment variables:", "```bash", "export GOOGLE_API_KEY='your-key'", "export GOOGLE_CSE_ID='your-cse-id'", "```"]
    (OUT / "google-intel.md").write_text("\n".join(lines), encoding="utf-8")
    return payload
