#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from cai_confidence_policy import score_candidate

OUT = Path("reports/output/final-dashboard")

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".txt", ".xml", ".map",
)
STATIC_WORDS = {"blog", "help", "docs", "documentation", "article", "marketing", "about", "contact", "privacy", "terms"}
STATE_CHANGE_WORDS = {"update", "change", "delete", "remove", "create", "add", "purchase", "checkout", "order", "settings", "password", "profile", "transfer", "submit"}
OBJECT_WORDS = {"id", "uid", "user", "account", "order", "invoice", "object", "tenant", "profile", "customer", "booking", "cart", "payment"}
API_WORDS = {"api", "graphql", "ajax", "json", "data", "v1", "v2", "rest"}
TOKEN_WORDS = {"authorization", "bearer", "jwt", "session", "cookie", "set-cookie", "token", "csrf", "xsrf"}
DB_ERROR_PATTERNS = ["sql syntax", "mysql", "postgres", "sqlite", "ora-", "odbc", "jdbc", "database error", "stack trace", "traceback", "exception", "debug"]


def short(value: Any, n: int = 500) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def path_from_url(value: str) -> str:
    parsed = urlparse(str(value or ""))
    return parsed.path or "/"


def params_from_url(value: str) -> list[str]:
    parsed = urlparse(str(value or ""))
    return [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]


def joined(item: dict[str, Any]) -> str:
    return " ".join(str(v) for v in item.values() if v not in (None, "", [], {})).lower()


def value(item: dict[str, Any], keys: list[str], fallback: str = "") -> str:
    for key in keys:
        if item.get(key) not in (None, "", [], {}):
            return str(item.get(key))
    return fallback


def vulnerability_type(item: dict[str, Any]) -> str:
    text = " ".join(str(item.get(k, "")) for k in ["vulnerability_type", "type", "category", "title", "what_found", "module"]).lower()
    if any(x in text for x in ["idor", "bola", "object level", "object authorization", "unauthorized object"]):
        return "IDOR/BOLA"
    if any(x in text for x in ["sqli", "sql injection", "database"]):
        return "SQLi"
    if "csrf" in text or "cross-site request" in text:
        return "CSRF"
    if "ssrf" in text:
        return "SSRF"
    if "open redirect" in text or "redirect" in text or "navigation" in text:
        return "Open Redirect"
    if "cors" in text:
        return "CORS"
    if any(x in text for x in ["jwt", "auth", "session", "token", "cookie"]):
        return "Auth/JWT"
    if any(x in text for x in ["safe parameter", "parameter", "canary", "marker", "reflection", "reflected"]):
        return "Safe Parameter Review"
    if "header" in text:
        return "Header Hardening"
    return short(value(item, ["type", "category", "what_found", "title"], "General Review"), 70)


def where_found(item: dict[str, Any], target: str) -> str:
    return value(item, ["tested_url", "where_found", "url", "endpoint", "item", "target"], target)


def evidence_text(item: dict[str, Any]) -> str:
    return value(item, ["evidence_detail", "evidence", "why_flagged", "reason", "decision", "safe_check", "verdict", "tail"], "")


def is_static_path(path: str) -> bool:
    p = path.lower()
    if p.endswith(STATIC_EXTENSIONS):
        return True
    parts = {x for x in re.split(r"[/_.-]+", p) if x}
    return bool(parts & STATIC_WORDS)


def eligibility(item: dict[str, Any], vtype: str, target: str) -> tuple[bool, str]:
    text = joined(item)
    where = where_found(item, target)
    path = path_from_url(where)
    params = set(params_from_url(where) + [str(item.get("parameter") or "")])
    path_parts = {x for x in re.split(r"[/_.-]+", path.lower()) if x}

    if vtype == "IDOR/BOLA":
        if is_static_path(path):
            return False, "ineligible: static/help/marketing content is not object-specific data"
        if (path_parts | {p.lower() for p in params}) & OBJECT_WORDS or re.search(r"/[0-9a-f-]{6,}(/|$)", path.lower()):
            return True, "passed: endpoint appears object/account identifier tied"
        return False, "ineligible: no account-specific or object-specific identifier evidence"
    if vtype == "SQLi":
        if any(x in text for x in ["response diff", "status code change", "body structure", "data lookup", "different valid input", *DB_ERROR_PATTERNS]):
            return True, "passed: observable data lookup variation or server-side error evidence"
        return False, "ineligible: parameter did not show observable data-lookup variation"
    if vtype == "CSRF":
        if any(x in text or x in path.lower() for x in STATE_CHANGE_WORDS):
            return True, "passed: state-changing endpoint indicators present"
        return False, "ineligible: read-only endpoint or no state-changing action evidence"
    if vtype in {"SSRF", "Open Redirect"}:
        if any(x in text for x in ["location", "redirect", "callback", "listener", "outbound", "fetch", "external", "example.invalid"]):
            return True, "passed: redirect/fetch behavior evidence present"
        return False, "ineligible: parameter presence without redirect/fetch behavior"
    if vtype == "CORS":
        if not ((path_parts & API_WORDS) or any(x in text for x in ["api", "json", "data endpoint", "access-control-allow-origin"])):
            return False, "ineligible: not an API/data endpoint"
        if "access-control-allow-origin" in text or "access-control-allow-credentials" in text:
            return True, "passed: captured CORS header evidence on data endpoint"
        return False, "ineligible: missing captured CORS header pair"
    if vtype == "Auth/JWT":
        if any(x in text for x in TOKEN_WORDS):
            return True, "passed: token/session artifact present in captured evidence"
        return False, "ineligible: auth/session wording without token or session artifact"
    if vtype == "Safe Parameter Review":
        if any(x in text for x in ["marker", "canary", "safe parameter", "reflected", "reflection", "location", "header", "body"]):
            return True, "passed: safe structural marker observation exists"
        return False, "ineligible: no behavioral evidence beyond parameter naming"
    if evidence_text(item) or any(x in text for x in ["header", "cookie", "diff", "evidence", "observed", "missing"]):
        return True, "passed: generic evidence artifact present"
    return False, "ineligible: no comparable evidence artifact"


def evidence_type_and_detail(item: dict[str, Any]) -> tuple[str | None, str]:
    text = joined(item)
    ev = evidence_text(item) or text
    if any(x in text for x in ["account a", "account b", "cross-account", "cross session", "request id", "session a", "session b"]):
        return "cross-session/cross-account comparison", short(ev, 650)
    if any(x in text for x in DB_ERROR_PATTERNS):
        return "server-side error signature", short(ev, 650)
    if any(x in text for x in ["access-control-allow-origin", "access-control-allow-credentials", "origin header"]):
        return "header inspection", short(ev, 650)
    if any(x in text for x in ["location header", "redirect location", "callback", "listener", "outbound fetch", "external redirect", "example.invalid"]):
        return "redirect/fetch target confirmation", short(ev, 650)
    if any(x in text for x in ["response diff", "structural diff", "status code change", "body structure", "header change", "response time", "baseline", "control"]):
        return "structural response diff", short(ev, 650)
    if any(x in text for x in ["marker", "canary", "safe parameter", "reflected", "reflection observed"]):
        return "structural response diff", short(ev, 650)
    return None, ""


def control_result(item: dict[str, Any]) -> str:
    direct = value(item, ["control_comparison_result", "control", "baseline", "baseline_result"], "")
    if direct:
        return short(direct, 500)
    text = joined(item)
    if "baseline" in text or "control" in text:
        return "Control/baseline comparison referenced in source evidence; inspect source module for full artifact."
    return "No explicit control/baseline artifact captured in source evidence."


def evidence_strength(item: dict[str, Any]) -> int:
    text = joined(item)
    score = 0
    for needle in ["response diff", "structural diff", "baseline", "control", "request id", "access-control-allow-origin", "location header", "callback", "stack trace", "database error", "confirmed", "validated", "verified", "reproduced"]:
        if needle in text:
            score += 2
    if evidence_text(item):
        score += 1
    if any(x in text for x in ["marker", "canary", "reflected", "reflection"]):
        score += 1
    return score


def stable_artifact_id(item: dict[str, Any], where: str, evidence_detail: str) -> str:
    raw = value(item, ["request_id", "response_id", "evidence_id", "id"], "") or f"{where}|{evidence_detail}"
    return hashlib.sha256(str(raw).encode("utf-8", errors="ignore")).hexdigest()[:16]


def dedup(raw: list[dict[str, Any]], target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in raw:
        vtype = vulnerability_type(item)
        path = path_from_url(where_found(item, target))
        enriched = dict(item)
        enriched["_vulnerability_type"] = vtype
        enriched["_url_path"] = path
        groups[(vtype, path)].append(enriched)
    unique: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    for key, items in groups.items():
        items_sorted = sorted(items, key=evidence_strength, reverse=True)
        representative = dict(items_sorted[0])
        representative["dedup_group_size"] = len(items)
        unique.append(representative)
        for duplicate in items_sorted[1:]:
            duplicates.append({
                "vulnerability_type": key[0],
                "url_path": key[1],
                "reason": "duplicate: same vulnerability_type and URL path",
                "where_found": where_found(duplicate, target),
            })
    return unique, duplicates, {"raw": len(raw), "unique": len(unique)}


def confirm_findings(raw_findings: list[dict[str, Any]], target: str) -> dict[str, Any]:
    unique, duplicates, counts = dedup(raw_findings, target)
    surface: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    needs_signal: list[dict[str, Any]] = []

    for item in unique:
        vtype = str(item.get("_vulnerability_type") or vulnerability_type(item))
        where = where_found(item, target)
        path = str(item.get("_url_path") or path_from_url(where))
        param = item.get("parameter") or (params_from_url(where)[0] if params_from_url(where) else "n/a")
        ok, elig_reason = eligibility(item, vtype, target)
        if not ok:
            suppressed.append({"vulnerability_type": vtype, "url_path": path, "where_found": where, "reason": elig_reason, "dedup_group_size": int(item.get("dedup_group_size", 1))})
            continue
        etype, edetail = evidence_type_and_detail(item)
        if not etype:
            needs_signal.append({"vulnerability_type": vtype, "url_path": path, "where_found": where, "reason": "low confidence: passed eligibility gate only, no sufficient behavioral evidence artifact", "dedup_group_size": int(item.get("dedup_group_size", 1))})
            continue
        control = control_result(item)
        score = score_candidate(vulnerability_type=vtype, item=item, evidence_type=etype, evidence_detail=edetail, control_comparison_result=control)
        conf = str(score["confidence"])
        if conf == "low":
            needs_signal.append({"vulnerability_type": vtype, "url_path": path, "where_found": where, "reason": "low confidence: failed weighted scoring threshold", "dedup_group_size": int(item.get("dedup_group_size", 1)), "confidence_score": score["confidence_score"], "score_breakdown": score["score_breakdown"]})
            continue
        classification = str(score["classification"])
        confirmed = classification == "CONFIRMED"
        source = value(item, ["source", "module", "how_found"], "confirmation_engine")
        title = value(item, ["what_found", "title", "name", "type", "category"], vtype)
        row = {
            "vulnerability_type": vtype,
            "url_path": path,
            "dedup_group_size": int(item.get("dedup_group_size", 1)),
            "eligibility_check": elig_reason,
            "evidence_type": etype,
            "evidence_detail": edetail,
            "confidence": conf,
            "confidence_score": score["confidence_score"],
            "score_breakdown": score["score_breakdown"],
            "control_comparison_result": control,
            "false_positive_risk_notes": score["false_positive_risk_notes"],
            "classification": classification,
            "source": source,
            "what_found": short(title, 140),
            "type": vtype,
            "where_found": short(where, 300),
            "path": path,
            "query": urlparse(where).query,
            "parameter": param or "n/a",
            "how_found": short(source, 220),
            "evidence": edetail,
            "evidence_artifact_id": stable_artifact_id(item, where, edetail),
            "confirmation_status": "Confirmed" if confirmed else "Review lead - not confirmed",
            "confirmed": confirmed,
            "confirmation_reason": score["decision_rationale"],
            "reportability": score["reportability"],
            "safe_confirmation_plan": "Use only existing approved non-destructive comparison evidence. Add reproduction/control artifacts before upgrading confidence.",
            "status": classification.lower().replace(" ", "_"),
        }
        surface.append(row)

    suppressed.extend(duplicates)
    return {
        "generated_at": time.time(),
        "deduplication": {"raw_count": counts["raw"], "unique_count": counts["unique"], "dedup_ratio": f"{counts['raw']} -> {counts['unique']}", "duplicates_suppressed": len(duplicates)},
        "summary": {
            "surface_count": len(surface),
            "confirmed": len([x for x in surface if x.get("classification") == "CONFIRMED"]),
            "review_leads": len([x for x in surface if x.get("classification") == "REVIEW LEAD"]),
            "noise_suppressed": len(suppressed),
            "needs_more_signal": len(needs_signal),
            "high_confidence": len([x for x in surface if x.get("confidence") == "high"]),
            "medium_confidence": len([x for x in surface if x.get("confidence") == "medium"]),
            "avg_confidence_score": round(sum(float(x.get("confidence_score", 0.0)) for x in surface) / len(surface), 3) if surface else 0.0,
        },
        "findings": [x for x in surface if x.get("classification") == "CONFIRMED"],
        "review_leads": [x for x in surface if x.get("classification") == "REVIEW LEAD"],
        "surface_findings": surface,
        "suppressed_noise": suppressed,
        "needs_more_signal": needs_signal,
    }


def write_confirmation_reports(target_slug: str, payload: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{target_slug}-confirmation-engine.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / f"{target_slug}-suppressed-noise.json").write_text(json.dumps(payload.get("suppressed_noise", []), indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Vulnerability Finding Confirmation Engine",
        "",
        "## Stage 0 — Deduplication",
        f"Dedup ratio: `{payload['deduplication']['dedup_ratio']}`",
        f"Duplicates suppressed: `{payload['deduplication']['duplicates_suppressed']}`",
        "",
        "## Stage 1 — Eligibility Gate",
        "Class-specific checks are applied before scoring. Ineligible candidates are suppressed as noise.",
        "",
        "## Stage 2 — Evidence Requirements",
        "Only captured comparable artifacts are accepted: structural diff, cross-session comparison, server-side error, redirect/fetch confirmation, or header inspection.",
        "",
        "## Stage 3 — Confidence Scoring",
        "Confidence = evidence_strength*0.4 + reproducibility*0.3 + impact_estimate*0.3.",
        "LOW goes to needs-more-signal. MEDIUM becomes a review lead. HIGH can become confirmed only when comparable evidence supports it.",
        "",
        "## Stage 4 — Output",
        f"Confirmed: `{payload['summary']['confirmed']}`",
        f"Review leads: `{payload['summary']['review_leads']}`",
        f"Noise suppressed: `{payload['summary']['noise_suppressed']}`",
        f"Needs more signal: `{payload['summary']['needs_more_signal']}`",
        f"Average confidence score: `{payload['summary']['avg_confidence_score']}`",
    ]
    (OUT / f"{target_slug}-confirmation-methodology.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Confirm, suppress, and score raw VulnScope findings from JSON")
    parser.add_argument("--input", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--slug", required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    raw = data if isinstance(data, list) else data.get("findings", [])
    payload = confirm_findings(raw, args.target)
    write_confirmation_reports(args.slug, payload)
    print(json.dumps({"summary": payload["summary"], "deduplication": payload["deduplication"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
