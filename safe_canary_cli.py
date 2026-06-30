#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from target_scope_guard import normalize_target, url_in_target_scope

OUT = Path("reports/output/safe-canary")
NORMALIZED = Path("reports/output/normalized/normalized-evidence.json")
TOP100_ROOT = Path("reports/output/top100-tools")
USER_AGENT = "VulnScope-SafeCanary/1.0 (+authorized-safe-review)"
SAFE_PARAM_NAMES = ["q", "s", "search", "query", "keyword", "term", "ref", "page", "next", "return", "redirect"]
URL_RE = re.compile(r"https?://[^\s'\"<>),]+", re.I)


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return (parsed.hostname or parsed.netloc or target).split(":")[0].lower().strip()


def domain_slug(target: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", host_from_target(target)).strip("-.") or "target"


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def collect_urls(target: str, max_urls: int) -> list[str]:
    target = normalize_target(target)
    urls: set[str] = {target}

    normalized = load_json(NORMALIZED)
    if isinstance(normalized, dict):
        for item in normalized.get("endpoints", [])[:1000]:
            if isinstance(item, dict) and item.get("url"):
                url = str(item["url"])
                if url_in_target_scope(url, target):
                    urls.add(url)

    top_dir = TOP100_ROOT / domain_slug(target) / "outputs"
    if top_dir.exists():
        for p in top_dir.rglob("*.txt"):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")[:2_000_000]
            except Exception:
                continue
            for match in URL_RE.findall(text):
                url = match.rstrip("),.;]")
                if url_in_target_scope(url, target):
                    urls.add(url)

    def score(url: str) -> tuple[int, int, str]:
        parsed = urlparse(url)
        param_count = len(parse_qsl(parsed.query, keep_blank_values=True))
        return (-param_count, len(parsed.path), url)

    return sorted(urls, key=score)[:max_urls]


def canary_urls(url: str, canary: str, per_url_limit: int) -> list[tuple[str, str, str]]:
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    candidates: list[tuple[str, str, str]] = []

    if existing:
        for name, _ in existing[:per_url_limit]:
            updated = [(k, canary if k == name else v) for k, v in existing]
            test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            candidates.append((name, test_url, "replace_existing_param"))
    else:
        for name in SAFE_PARAM_NAMES[:per_url_limit]:
            test_url = urlunparse(parsed._replace(query=urlencode({name: canary})))
            candidates.append((name, test_url, "add_safe_param"))
    return candidates


def snippet_around(text: str, marker: str, limit: int = 220) -> str:
    idx = text.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - limit // 2)
    end = min(len(text), idx + len(marker) + limit // 2)
    return " ".join(text[start:end].split())[:limit]


def classify_result(where: list[str], param: str, url: str) -> tuple[str, float, str]:
    if not where:
        return "not_reflected", 0.0, "No harmless canary reflection observed."
    low = " ".join(where + [param, url]).lower()
    if "location" in low or param.lower() in {"next", "return", "redirect"}:
        return "redirect_or_navigation_candidate", 0.65, "Harmless canary appeared in a redirect/navigation-related surface."
    if "body" in low:
        return "reflected_parameter_candidate", 0.70, "Harmless canary appeared in the response body."
    return "canary_observed", 0.55, "Harmless canary appeared in response metadata."


def request_once(url: str, timeout: int) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5"},
            timeout=timeout,
            allow_redirects=False,
        )
        body = response.text[:250_000] if response.text else ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        return {"ok": True, "status_code": response.status_code, "content_type": response.headers.get("content-type", ""), "location": response.headers.get("location", ""), "headers": headers_text, "body": body}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}


def run_canary_review(target: str, canary: str = "CANARY_123", max_urls: int = 80, per_url_limit: int = 3, delay: float = 0.35, timeout: int = 10) -> dict[str, Any]:
    target = normalize_target(target)
    OUT.mkdir(parents=True, exist_ok=True)
    urls = collect_urls(target, max_urls=max_urls)
    results: list[dict[str, Any]] = []
    started = time.time()

    print("=" * 72, flush=True)
    print("VULNSCOPE SAFE CANARY PARAMETER REVIEW", flush=True)
    print(f"Target: {target}", flush=True)
    print(f"Marker: {canary}", flush=True)
    print("Mode: GET-only, no POST, no login, no exploit payloads, no data modification", flush=True)
    print("=" * 72, flush=True)

    total_tests = sum(len(canary_urls(url, canary, per_url_limit)) for url in urls)
    done = 0
    for url in urls:
        if not url_in_target_scope(url, target):
            continue
        for param, test_url, mode in canary_urls(url, canary, per_url_limit):
            done += 1
            if not url_in_target_scope(test_url, target):
                continue
            print(f"[canary {done}/{max(1,total_tests)}] {param} -> {test_url[:160]}", flush=True)
            response = request_once(test_url, timeout=timeout)
            where: list[str] = []
            evidence = ""
            if response.get("ok"):
                body = str(response.get("body", ""))
                headers = str(response.get("headers", ""))
                location = str(response.get("location", ""))
                if canary in body:
                    where.append("body")
                    evidence = snippet_around(body, canary)
                if canary in headers:
                    where.append("headers")
                    if not evidence:
                        evidence = snippet_around(headers, canary)
                if canary in location:
                    where.append("location")
                    if not evidence:
                        evidence = location[:220]
                category, confidence, reason = classify_result(where, param, test_url)
                results.append({
                    "title": "Harmless canary parameter reflection observed" if where else "Canary parameter not reflected",
                    "category": category,
                    "parameter": param,
                    "mode": mode,
                    "url": url,
                    "tested_url": test_url,
                    "where_found": test_url,
                    "status_code": response.get("status_code"),
                    "content_type": response.get("content_type"),
                    "canary": canary,
                    "reflected_in": where,
                    "evidence": evidence,
                    "why_flagged": reason,
                    "confidence": confidence,
                    "status": "review_needed" if where else "informational",
                    "how_to_confirm": "Repeat the same GET request with a harmless marker, confirm the marker location in the response, inspect whether it is plain text, URL, attribute, script, or JSON context, and only escalate if real impact is proven safely.",
                })
            else:
                results.append({"title": "Canary request failed", "category": "canary_request_error", "parameter": param, "url": url, "tested_url": test_url, "where_found": test_url, "error": response.get("error"), "status": "informational", "confidence": 0.0})
            time.sleep(max(0.0, delay))

    findings = [r for r in results if r.get("reflected_in")]
    payload = {
        "target": target,
        "generated_at": time.time(),
        "summary": {
            "urls_considered": len(urls),
            "tests_run": len(results),
            "canary_observations": len(findings),
            "seconds": round(time.time() - started, 2),
        },
        "safety": {
            "method": "GET-only harmless marker review",
            "canary": canary,
            "no_post_requests": True,
            "no_state_changing_methods": True,
            "no_exploit_payloads": True,
            "target_scope_only": True,
        },
        "findings": findings,
        "results": results,
    }
    (OUT / "safe-canary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# Safe Canary Parameter Review — {host_from_target(target)}",
        "",
        f"Target: `{target}`",
        f"Marker: `{canary}`",
        "Mode: `GET-only harmless marker review`",
        f"URLs considered: `{len(urls)}`",
        f"Tests run: `{len(results)}`",
        f"Canary observations: `{len(findings)}`",
        "",
        "## Safety Controls",
        "- No POST/PUT/PATCH/DELETE requests.",
        "- No login actions.",
        "- No exploit payloads.",
        "- No data modification attempts.",
        "- Only target-scoped URLs are tested.",
        "",
        "## Observations",
    ]
    if not findings:
        lines.append("No reflected canary observations were found.")
    for idx, item in enumerate(findings[:50], 1):
        lines += [
            f"### {idx}. {item['category']}",
            f"- Parameter: `{item['parameter']}`",
            f"- Tested URL: `{item['tested_url']}`",
            f"- Reflected in: `{', '.join(item.get('reflected_in', []))}`",
            f"- Evidence: `{html.escape(str(item.get('evidence', '')))}`",
            f"- How to confirm: {item['how_to_confirm']}",
            "",
        ]
    (OUT / "safe-canary.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "report": "reports/output/safe-canary/safe-canary.md"}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe GET-only CANARY_123 parameter reflection review")
    parser.add_argument("--target", required=True)
    parser.add_argument("--canary", default="CANARY_123")
    parser.add_argument("--max-urls", type=int, default=80)
    parser.add_argument("--per-url-limit", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.35)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--scope-policy", default=None)
    args = parser.parse_args()
    run_canary_review(args.target, canary=args.canary, max_urls=args.max_urls, per_url_limit=args.per_url_limit, delay=args.delay, timeout=args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
