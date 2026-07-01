#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, normalize_target

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NUM_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
PATH_ID_RE = re.compile(r"/(\d{2,}|[0-9a-f]{8,})(?=/|$)", re.I)


def load_json_safe(path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="input_inventory", action="load_json", error=exc, fallback_used="empty_input")


def infer_value_type(name: str, value: str) -> str:
    name_l = str(name or "").lower()
    value_s = str(value or "").strip()
    if UUID_RE.match(value_s):
        return "uuid"
    if NUM_RE.match(value_s):
        return "numeric"
    if EMAIL_RE.match(value_s):
        return "email"
    if DATE_RE.match(value_s):
        return "date"
    if value_s.lower() in {"true", "false", "yes", "no", "on", "off", "asc", "desc", "json", "xml"}:
        return "enum"
    if value_s.startswith(("http://", "https://", "//")) or name_l in {"url", "return", "next", "target", "callback"}:
        return "url"
    if name_l in {"file", "filename", "path", "download", "document", "asset"}:
        return "file"
    if value_s:
        try:
            padded = value_s + "=" * (-len(value_s) % 4)
            decoded = base64.b64decode(padded.encode(), validate=True)
            if decoded and len(decoded) >= 4:
                return "base64"
        except Exception:
            pass
    if name_l in {"q", "s", "search", "query", "keyword", "term", "name"}:
        return "free-text"
    return "unknown" if not value_s else "free-text"


def classify_endpoint(path: str) -> str:
    low = str(path or "/").lower()
    if "/api/" in low or low.startswith("/api") or "graphql" in low or low.endswith(".json"):
        return "api-like"
    if any(x in low for x in ["login", "logout", "auth", "register", "reset", "password", "session"]):
        return "identity-related"
    if any(x in low for x in ["upload", "import"]):
        return "upload-related"
    if any(x in low for x in ["pay", "checkout", "invoice", "billing", "order"]):
        return "payment-related"
    if any(x in low for x in ["callback", "return"]):
        return "navigation-related"
    if any(x in low for x in ["download", "file", "export"]):
        return "file-related"
    if any(x in low for x in ["search", "query"]):
        return "search-related"
    return "public-page"


def template_path(path: str) -> str:
    path = path or "/"
    path = re.sub(r"/[0-9]+(?=/|$)", "/{id}", path)
    path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{token}", path, flags=re.I)
    return path


def extract_endpoint(url: str) -> dict[str, Any]:
    parsed = urlparse(str(url))
    inputs = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        inputs.append({"name": name, "sample_value": value, "inferred_type": infer_value_type(name, value), "source": "query_string"})
    for idx, value in enumerate(PATH_ID_RE.findall(parsed.path or ""), 1):
        inputs.append({"name": f"path_segment_{idx}", "sample_value": value, "inferred_type": "numeric" if value.isdigit() else "opaque-id", "source": "path_segment"})
    return {
        "url": str(url),
        "host": parsed.hostname or "",
        "path": parsed.path or "/",
        "path_template": template_path(parsed.path or "/"),
        "endpoint_class": classify_endpoint(parsed.path or "/"),
        "inputs": inputs,
        "input_count": len(inputs),
    }


def build_inventory(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    out_dir = cai_output_dir(target)
    recon = load_json_safe(out_dir / "recon-agent.json")
    urls = [target]
    if isinstance(recon, dict):
        urls.extend(recon.get("historical_urls", []) or [])
    seen = set()
    endpoints = []
    for url in urls[:1000]:
        if url in seen:
            continue
        seen.add(url)
        try:
            endpoints.append(extract_endpoint(str(url)))
        except Exception as exc:
            endpoints.append({"url": str(url), "status": "handled_error", "detail": handled_error(component="input_inventory", action="extract_endpoint", error=exc)})
    all_inputs = [p for e in endpoints for p in e.get("inputs", [])]
    type_counts: dict[str, int] = {}
    for item in all_inputs:
        key = str(item.get("inferred_type") or "unknown")
        type_counts[key] = type_counts.get(key, 0) + 1
    return {
        "target": target,
        "host": host_from_target(target),
        "generated_at": time.time(),
        "layer": 2,
        "mode": "passive-input-inference",
        "summary": {"endpoints": len(endpoints), "inputs": len(all_inputs), "input_types": type_counts},
        "endpoints": endpoints,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 2 reads existing Layer 1 output and does not contact the target."},
    }


def write_inventory_reports(target: str, inventory: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "input-inventory.json", inventory)
    checkpoint = {"checkpoint": 2, "name": "Parameter & Endpoint Analysis Agent", "status": "completed", "target": target, "host": inventory.get("host"), "summary": inventory.get("summary", {}), "reports": {"json": str(out_dir / "input-inventory.json"), "markdown": str(out_dir / "input-inventory.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-2.json", checkpoint)
    lines = ["# CAI Superior Checkpoint 2 — Parameter & Endpoint Analysis", "", f"Target: `{target}`", f"Endpoints: `{inventory.get('summary', {}).get('endpoints', 0)}`", f"Inputs: `{inventory.get('summary', {}).get('inputs', 0)}`", "", "## Input Types"]
    for key, count in sorted((inventory.get("summary", {}).get("input_types", {}) or {}).items()):
        lines.append(f"- `{key}`: `{count}`")
    lines += ["", "## Endpoints"]
    for e in inventory.get("endpoints", [])[:250]:
        lines.append(f"- `{e.get('endpoint_class')}` `{e.get('path_template')}` inputs=`{e.get('input_count', 0)}` url=`{e.get('url')}`")
    write_markdown(out_dir / "input-inventory.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior Layer 2 endpoint input inventory")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    inventory = build_inventory(args.target)
    print(json.dumps(write_inventory_reports(args.target, inventory), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
