from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from normalizers.evidence import normalize_all

OUT = Path("reports/output/api-intel")

API_HINTS = ["/api/", "/v1/", "/v2/", "/graphql", "/gql", "swagger", "openapi", "postman"]
SENSITIVE_OBJECT_WORDS = ["user", "account", "order", "invoice", "payment", "profile", "tenant", "org", "team"]


def build_api_intel(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    ev = normalize_all(target)
    endpoints = ev.get("endpoints", [])
    api = []
    for e in endpoints:
        low = e["url"].lower()
        if any(h in low for h in API_HINTS) or "api_surface" in e.get("risk_tags", []):
            tags = []
            if "graphql" in low or "gql" in low:
                tags.append("graphql_candidate")
            if any(w in low for w in SENSITIVE_OBJECT_WORDS):
                tags.append("object_authorization_review")
            if any(p in e.get("params", []) for p in ["id", "user", "account", "tenant", "org"]):
                tags.append("bola_parameter_review")
            if any(x in low for x in ["delete", "update", "create", "transfer", "checkout"]):
                tags.append("mutation_or_state_review")
            api.append({**e, "api_tags": sorted(set(tags))})
    payload = {"target": target or ev.get("target"), "generated_at": time.time(), "summary": {"api_endpoints": len(api), "graphql": len([x for x in api if "graphql_candidate" in x.get("api_tags", [])]), "object_review": len([x for x in api if "object_authorization_review" in x.get("api_tags", []) or "bola_parameter_review" in x.get("api_tags", [])])}, "api_endpoints": api}
    (OUT / "api-intel.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope API Intelligence — {payload['target']}", "", f"API endpoints: `{len(api)}`", f"GraphQL candidates: `{payload['summary']['graphql']}`", f"Object/auth review: `{payload['summary']['object_review']}`", "", "## API Surfaces"]
    for item in api[:150]:
        lines.append(f"- `{item['url']}` tags=`{','.join(item.get('api_tags', []))}` params=`{','.join(item.get('params', []))}`")
    (OUT / "api-intel.md").write_text("\n".join(lines), encoding="utf-8")
    return payload
