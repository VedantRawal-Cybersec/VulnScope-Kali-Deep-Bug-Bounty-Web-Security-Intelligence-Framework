from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

OUT = Path("reports/output/artemis/burp-safe")

INPUTS = [
    "reports/output/artemis/run/artemis-run.json",
    "reports/output/normalized/normalized-evidence.json",
    "reports/output/artemis/predictions",
    "reports/output/evidence-cards/evidence-cards.json",
]

ISSUE_ENDPOINTS = [
    "/v2/issues",
    "/v2/findings",
    "/issues",
    "/findings",
]

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "token", "secret", "password", "api_key", "apikey", "key"}


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in SENSITIVE_KEYS:
                out[k] = "[redacted]"
            else:
                out[k] = redact_value(v)
        return out
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        clean = value
        for word in SENSITIVE_KEYS:
            clean = clean.replace(word, word[:2] + "[redacted]")
        return clean[:5000]
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def collect_high_risk_endpoints(target: str | None = None, limit: int = 80) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}

    def add(url: str, source: str, reason: str, confidence: float = 0.5) -> None:
        if not url.startswith(("http://", "https://")):
            return
        if target:
            target_host = urlparse(target if "://" in target else "https://" + target).netloc.split(":")[0]
            host = urlparse(url).netloc.split(":")[0]
            if target_host and host and not host.endswith(target_host):
                return
        row = endpoints.setdefault(url, {"url": url, "sources": [], "reasons": [], "confidence": confidence})
        if source not in row["sources"]:
            row["sources"].append(source)
        if reason not in row["reasons"]:
            row["reasons"].append(reason)
        row["confidence"] = max(float(row.get("confidence", 0)), confidence)

    # Normalized evidence.
    norm = load_json(Path("reports/output/normalized/normalized-evidence.json"))
    if isinstance(norm, dict):
        for e in norm.get("endpoints", []):
            if not isinstance(e, dict):
                continue
            tags = e.get("risk_tags", []) or []
            params = e.get("params", []) or []
            if tags or params:
                add(str(e.get("url")), "normalized", f"risk_tags={','.join(tags)} params={','.join(params)}", 0.55 + min(0.25, 0.05 * len(tags)))

    # ARTEMIS prediction files.
    pred_dir = Path("reports/output/artemis/predictions")
    if pred_dir.exists():
        for path in pred_dir.glob("*-predictions.json"):
            data = load_json(path)
            if not isinstance(data, dict):
                continue
            for p in data.get("predictions", []):
                if isinstance(p, dict) and p.get("where"):
                    add(str(p.get("where")), "artemis_prediction", str(p.get("type")), float(p.get("confidence", 0.5)))

    # Evidence cards/reportability.
    for path in [Path("reports/output/evidence-cards/evidence-cards.json"), Path("reports/output/reportability/reportability.json")]:
        data = load_json(path)
        for obj in walk(data):
            url = obj.get("url") or obj.get("endpoint") or obj.get("where") or obj.get("where_found")
            if isinstance(url, str):
                add(url, path.name, str(obj.get("title") or obj.get("category") or "review_candidate"), float(obj.get("reportability_score", 0.5) or 0.5))

    ranked = sorted(endpoints.values(), key=lambda x: float(x.get("confidence", 0)), reverse=True)
    return ranked[:limit]


class BurpSafeBridge:
    """Safe Burp bridge.

    This adapter does not start active scans, fuzz parameters, or launch Burp.
    It prepares scope seeds and imports already-existing Burp findings/passive issues
    through the API when available.
    """

    def __init__(self, burp_url: str | None = None, api_key: str | None = None) -> None:
        self.burp_url = (burp_url or os.environ.get("BURP_URL") or "http://127.0.0.1:1337").rstrip("/")
        self.api_key = api_key or os.environ.get("BURP_API_KEY") or ""
        self.headers = {"Content-Type": "application/json"}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def request_json(self, path: str) -> tuple[bool, Any]:
        try:
            resp = requests.get(self.burp_url + path, headers=self.headers, timeout=8)
            if resp.status_code >= 400:
                return False, {"status_code": resp.status_code, "text": resp.text[:500]}
            try:
                return True, resp.json()
            except Exception:
                return True, {"text": resp.text[:1000]}
        except Exception as exc:
            return False, {"error": str(exc)}

    def health(self) -> dict[str, Any]:
        checks = []
        for path in ["/v2/about", "/about", "/"]:
            ok, data = self.request_json(path)
            checks.append({"path": path, "ok": ok, "data": redact_value(data)})
            if ok:
                return {"reachable": True, "burp_url": self.burp_url, "working_path": path, "checks": checks}
        return {"reachable": False, "burp_url": self.burp_url, "checks": checks}

    def import_findings(self) -> list[dict[str, Any]]:
        imported = []
        for path in ISSUE_ENDPOINTS:
            ok, data = self.request_json(path)
            if not ok:
                continue
            rows = []
            if isinstance(data, dict):
                rows = data.get("issues") or data.get("findings") or data.get("items") or []
            elif isinstance(data, list):
                rows = data
            for item in rows if isinstance(rows, list) else []:
                if isinstance(item, dict):
                    imported.append({
                        "source": "burp_api",
                        "api_path": path,
                        "name": item.get("name") or item.get("issue_type") or item.get("type") or item.get("title"),
                        "severity": item.get("severity") or item.get("confidence"),
                        "url": item.get("url") or item.get("origin") or item.get("path"),
                        "description": redact_value(item.get("description") or item.get("detail") or ""),
                        "remediation": redact_value(item.get("remediation") or item.get("remediation_background") or ""),
                    })
        return imported


def run_burp_safe(target: str | None = None, limit: int = 80) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    bridge = BurpSafeBridge()
    endpoints = collect_high_risk_endpoints(target, limit=limit)
    health = bridge.health()
    findings = bridge.import_findings() if health.get("reachable") else []
    payload = {
        "target": target or "authorized-target",
        "generated_at": time.time(),
        "mode": "burp_safe_passive_bridge",
        "safety": {
            "starts_burp": False,
            "active_scan": False,
            "fuzzing": False,
            "state_changing_requests": False,
            "purpose": "Prepare Burp scope seeds and import already-existing Burp passive findings.",
        },
        "burp_health": health,
        "summary": {"scope_seeds": len(endpoints), "imported_findings": len(findings), "burp_reachable": bool(health.get("reachable"))},
        "scope_seeds": endpoints,
        "imported_findings": findings,
    }
    (OUT / "burp-safe.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "burp-scope-seeds.txt").write_text("\n".join([e["url"] for e in endpoints]), encoding="utf-8")
    lines = [
        "# ARTEMIS Burp Safe Bridge",
        "",
        "**Safe mode:** no active scan, no fuzzing, no exploit execution, no state-changing requests.",
        "",
        f"Burp reachable: `{health.get('reachable')}`",
        f"Scope seeds: `{len(endpoints)}`",
        f"Imported findings: `{len(findings)}`",
        "",
        "## High-Risk Scope Seeds for Burp",
    ]
    for e in endpoints[:80]:
        lines.append(f"- `{e['url']}` confidence=`{round(float(e.get('confidence', 0)), 2)}` reasons=`{'; '.join(e.get('reasons', [])[:2])}`")
    lines += ["", "## Imported Burp Findings"]
    for f in findings[:80]:
        lines += [f"### {f.get('name') or 'Burp finding'}", f"- Severity: `{f.get('severity')}`", f"- URL: `{f.get('url')}`", f"- Remediation: {str(f.get('remediation') or '')[:500]}", ""]
    if not health.get("reachable"):
        lines += ["", "## Setup", "Start Burp with REST API enabled, then set:", "```bash", "export BURP_URL='http://127.0.0.1:1337'", "export BURP_API_KEY='your-api-key-if-required'", "```"]
    (OUT / "burp-safe.md").write_text("\n".join(lines), encoding="utf-8")
    return payload
