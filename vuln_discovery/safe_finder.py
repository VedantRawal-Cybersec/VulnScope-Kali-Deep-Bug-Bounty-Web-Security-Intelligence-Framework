from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen

OUT_DIR = Path("reports/output/vuln-discovery")

SECRET_KEY_NAMES = {
    "token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "key",
    "secret", "password", "passwd", "pwd", "session", "sid", "auth", "jwt",
}

SECRET_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
]

SAFE_PATHS = ["/", "/robots.txt", "/sitemap.xml"]


@dataclass
class FindingCandidate:
    title: str
    severity: str
    confidence: str
    status: str
    category: str
    evidence: str
    affected: str
    recommendation: str
    exploit_used: bool = False
    destructive_action_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _request_url(url: str, timeout: int = 8) -> dict[str, Any]:
    req = Request(url, headers={"User-Agent": "VulnScope-SafeDiscovery/1.0"})
    started = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec: target is scope-checked by caller
            body = resp.read(2048)
            return {
                "url": url,
                "ok": True,
                "status": getattr(resp, "status", None),
                "headers": dict(resp.headers.items()),
                "sample_sha_hint": str(len(body)),
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    except Exception as exc:
        return {"url": url, "ok": False, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


def _header_lookup(headers: dict[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _cookie_findings(url: str, headers: dict[str, str]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in cookies:
        low = cookie.lower()
        cookie_name = cookie.split("=", 1)[0][:80]
        missing = []
        if "secure" not in low and urlparse(url).scheme == "https":
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(FindingCandidate(
                title="Session cookie security flags missing",
                severity="medium" if "HttpOnly" in missing else "low",
                confidence="high",
                status="confirmed_misconfiguration",
                category="cookie-hardening",
                evidence=f"Cookie `{cookie_name}` is missing: {', '.join(missing)}.",
                affected=url,
                recommendation="Set Secure, HttpOnly, and SameSite on session/auth cookies where applicable.",
            ))
    return findings


def _header_findings(url: str, headers: dict[str, str]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    parsed = urlparse(url)
    required = [
        ("Content-Security-Policy", "medium", "Add a strict CSP to reduce XSS impact and content injection risk."),
        ("X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", "low", "Set a privacy-preserving Referrer-Policy."),
    ]
    if parsed.scheme == "https":
        required.insert(0, ("Strict-Transport-Security", "medium", "Enable HSTS after verifying all subdomains support HTTPS."))
    for name, severity, recommendation in required:
        if not _header_lookup(headers, name):
            findings.append(FindingCandidate(
                title=f"Missing security header: {name}",
                severity=severity,
                confidence="high",
                status="confirmed_misconfiguration",
                category="security-header",
                evidence=f"Response from {url} did not include `{name}`.",
                affected=url,
                recommendation=recommendation,
            ))
    for disclosure in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        value = _header_lookup(headers, disclosure)
        if value:
            findings.append(FindingCandidate(
                title=f"Technology/version disclosure via {disclosure}",
                severity="info",
                confidence="high",
                status="review_candidate",
                category="information-disclosure",
                evidence=f"Header `{disclosure}` is present. Value redacted length: {len(value)}.",
                affected=url,
                recommendation="Remove unnecessary technology/version disclosure headers where possible.",
            ))
    findings.extend(_cookie_findings(url, headers))
    return findings


def _redacted_url_issue(raw_url: str) -> FindingCandidate | None:
    parsed = urlparse(raw_url)
    sensitive_keys = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() in SECRET_KEY_NAMES]
    if not sensitive_keys:
        return None
    safe_url = parsed._replace(query="<redacted-sensitive-query>").geturl()
    return FindingCandidate(
        title="Sensitive-looking value passed in URL query",
        severity="medium",
        confidence="medium",
        status="review_candidate",
        category="sensitive-data-exposure",
        evidence=f"Sensitive query key(s) detected and redacted: {', '.join(sorted(set(sensitive_keys)))}.",
        affected=safe_url,
        recommendation="Move secrets/tokens out of URLs. Use secure headers or server-side session handling.",
    )


def _secret_pattern_issue(text: str, affected: str) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(text or ""):
            findings.append(FindingCandidate(
                title="Secret-like pattern observed in captured traffic or script reference",
                severity="high",
                confidence="medium",
                status="review_candidate",
                category="secret-exposure",
                evidence="A secret/token-like pattern was detected. Value intentionally not stored.",
                affected=affected,
                recommendation="Rotate exposed values if validated, remove secrets from client-side code, and add secret scanning to CI.",
            ))
            break
    return findings


def _har_findings(har_path: str | Path) -> list[FindingCandidate]:
    p = Path(har_path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    entries = data.get("log", {}).get("entries", [])
    findings: list[FindingCandidate] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        if not url:
            continue
        issue = _redacted_url_issue(url)
        if issue and (issue.title, issue.affected) not in seen:
            findings.append(issue)
            seen.add((issue.title, issue.affected))
        parsed = urlparse(url)
        if parsed.path.lower().endswith((".js", ".mjs")):
            for item in _secret_pattern_issue(url, parsed._replace(query="").geturl()):
                if (item.title, item.affected) not in seen:
                    findings.append(item)
                    seen.add((item.title, item.affected))
        status = int(resp.get("status", 0) or 0)
        if status in {401, 403} and any(x in parsed.path.lower() for x in ["/admin", "/internal", "/debug"]):
            findings.append(FindingCandidate(
                title="High-value restricted endpoint observed",
                severity="info",
                confidence="medium",
                status="review_candidate",
                category="attack-surface",
                evidence=f"Endpoint returned restricted status {status}; no bypass attempted.",
                affected=parsed._replace(query="").geturl(),
                recommendation="Ensure this endpoint has server-side authorization, monitoring, and no sensitive metadata leakage.",
            ))
    return findings


def dedupe_findings(findings: list[FindingCandidate]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.affected, finding.evidence)
        if key not in seen:
            out.append(finding)
            seen.add(key)
    return out


def write_outputs(target: str, findings: list[FindingCandidate], probe_results: list[dict[str, Any]]) -> dict[str, Path]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "mode": "safe_non_exploit_discovery",
        "rules": [
            "No exploitation performed",
            "No destructive actions performed",
            "No credential capture or secret storage",
            "Candidates require human validation before reporting as exploitable vulnerabilities",
        ],
        "probe_results": probe_results,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "confirmed_misconfiguration": sum(1 for f in findings if f.status == "confirmed_misconfiguration"),
            "review_candidate": sum(1 for f in findings if f.status == "review_candidate"),
        },
    }
    json_path = OUT_DIR / "safe-vulnerability-candidates.json"
    md_path = OUT_DIR / "safe-vulnerability-candidates.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# Safe Vulnerability Discovery — {target}", "", "No exploit payloads, credential theft, destructive actions, or bypass attempts were used.", ""]
    for idx, finding in enumerate(findings, 1):
        lines += [
            f"## {idx}. {finding.title}",
            f"- Severity: `{finding.severity}`",
            f"- Confidence: `{finding.confidence}`",
            f"- Status: `{finding.status}`",
            f"- Category: `{finding.category}`",
            f"- Affected: `{finding.affected}`",
            f"- Evidence: {finding.evidence}",
            f"- Recommendation: {finding.recommendation}",
            "",
        ]
    if not findings:
        lines.append("No safe non-exploit candidates were identified from the available evidence.")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def run_safe_discovery(target: str, har_path: str | None = None, allow_probes: bool = True) -> dict[str, Any]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    base = parsed.geturl().rstrip("/")
    findings: list[FindingCandidate] = []
    probe_results: list[dict[str, Any]] = []
    if allow_probes:
        for path in SAFE_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            result = _request_url(url)
            probe_results.append(result)
            if result.get("ok") and path == "/":
                findings.extend(_header_findings(url, result.get("headers", {})))
    if har_path:
        findings.extend(_har_findings(har_path))
    findings = dedupe_findings(findings)
    paths = write_outputs(target, findings, probe_results)
    return {
        "target": target,
        "paths": {k: str(v) for k, v in paths.items()},
        "findings_total": len(findings),
        "confirmed_misconfiguration": sum(1 for f in findings if f.status == "confirmed_misconfiguration"),
        "review_candidate": sum(1 for f in findings if f.status == "review_candidate"),
    }
