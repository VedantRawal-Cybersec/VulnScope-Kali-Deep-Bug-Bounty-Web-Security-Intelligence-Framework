from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

OUT_DIR = Path("reports/output/auth/google-context")
STATE_DIR = Path("reports/output/auth/states")
AUTH_FILES = [
    "reports/output/auth/auth-crawl-account_a.json",
    "reports/output/auth/auth-crawl-account_b.json",
    "reports/output/auth/account-comparison.json",
]

@dataclass
class GoogleAuthCandidate:
    title: str
    category: str
    evidence: list[str]
    severity: str = "info"
    confidence: float = 0.0
    validation_status: str = "review_candidate"
    source: str = "google_context_review"
    notes: str = "No tokens, cookies, or credentials are copied into the report."
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class GoogleContextReview:
    """Bounded review of locally saved Google/OAuth browser context.

    This module reads local Playwright storage-state metadata and auth crawl
    summaries. It never prints secret values, uses tokens, sends emails, changes
    account settings, or performs privileged Google account actions.
    """
    def run(self) -> dict[str, Any]:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        started = time.time()
        states = self._load_state_summaries()
        auth_evidence = self._load_auth_evidence()
        candidates = self._review_states(states) + self._review_auth_evidence(auth_evidence)
        payload = {
            "mode": "google_authenticated_context_review",
            "started_at": started,
            "ended_at": time.time(),
            "rules": {"secret_output": False, "account_changes": False, "email_access": False, "google_api_actions": False, "state_change": False},
            "state_files_reviewed": [s["path"] for s in states],
            "candidates": [c.to_dict() for c in candidates],
            "summary": {"state_files": len(states), "candidates": len(candidates)},
        }
        (OUT_DIR / "google-context-review.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUT_DIR / "google-context-review.md").write_text(self._markdown(payload), encoding="utf-8")
        return payload

    def _load_state_summaries(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not STATE_DIR.exists():
            return out
        for path in sorted(STATE_DIR.glob("*google*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            cookies = data.get("cookies", []) if isinstance(data, dict) else []
            origins = data.get("origins", []) if isinstance(data, dict) else []
            out.append({
                "path": str(path),
                "cookie_count": len(cookies),
                "origin_count": len(origins),
                "cookie_domains": sorted({c.get("domain", "") for c in cookies if isinstance(c, dict)})[:25],
                "cookie_names": sorted({c.get("name", "") for c in cookies if isinstance(c, dict)})[:50],
                "missing_secure": len([c for c in cookies if isinstance(c, dict) and not c.get("secure")]),
                "missing_httponly": len([c for c in cookies if isinstance(c, dict) and not c.get("httpOnly")]),
                "missing_samesite": len([c for c in cookies if isinstance(c, dict) and not c.get("sameSite")]),
            })
        return out

    def _load_auth_evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for raw in AUTH_FILES:
            p = Path(raw)
            if not p.exists():
                continue
            try:
                out[raw] = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:
                out[raw] = {"error": str(exc)}
        return out

    def _review_states(self, states: list[dict[str, Any]]) -> list[GoogleAuthCandidate]:
        out: list[GoogleAuthCandidate] = []
        if not states:
            return [GoogleAuthCandidate("No Google storage-state file found yet", "google_auth_setup", [], "info", 0.30, notes="Run auth_mode.py --profile default --google-login --account a first.")]
        for state in states:
            ev = [state["path"]]
            if state.get("missing_secure"):
                out.append(GoogleAuthCandidate("Saved auth context contains cookies without Secure flag", "session_cookie_review", ev, "medium", 0.65))
            if state.get("missing_httponly"):
                out.append(GoogleAuthCandidate("Saved auth context contains cookies without HttpOnly flag", "session_cookie_review", ev, "low", 0.55))
            if state.get("missing_samesite"):
                out.append(GoogleAuthCandidate("Saved auth context contains cookies without SameSite attribute", "session_cookie_review", ev, "low", 0.55))
            if any("google" in d for d in state.get("cookie_domains", [])):
                out.append(GoogleAuthCandidate("Google-authenticated browser context is available for owned-account comparison", "google_auth_context", ev, "info", 0.70, notes="Use this only for owned accounts and application routes explicitly in scope."))
        return out

    def _review_auth_evidence(self, evidence: dict[str, Any]) -> list[GoogleAuthCandidate]:
        out: list[GoogleAuthCandidate] = []
        text = json.dumps(evidence, ensure_ascii=False, default=str).lower()
        if "accounts.google" in text or "oauth" in text:
            out.append(GoogleAuthCandidate("OAuth/Google login route observed in authenticated crawl evidence", "oauth_flow_review", list(evidence.keys()), "info", 0.62))
        if "difference" in text or "account-comparison" in text:
            out.append(GoogleAuthCandidate("Authenticated account comparison evidence available for access-control review", "authorization_review", list(evidence.keys()), "medium", 0.70))
        return out

    def _markdown(self, payload: dict[str, Any]) -> str:
        lines = ["# VulnScope Google Authenticated Context Review", "", "Bounded review only. Secret values are not printed or used.", "", "## Candidates"]
        for c in payload["candidates"]:
            lines += [f"- **{c['title']}**", f"  - Category: `{c['category']}`", f"  - Severity: `{c['severity']}`", f"  - Confidence: `{c['confidence']}`", ""]
        return "\n".join(lines)

def run_google_context_review() -> dict[str, Any]:
    return GoogleContextReview().run()
