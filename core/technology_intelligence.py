#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class TechnologyFinding:
    name: str
    category: str
    evidence: str
    confidence: int = 70
    version: str = ""


class TechnologyIntelligence:
    """Passive technology, platform, and advisory mapper.

    It identifies visible technologies and checks public advisory feeds when enabled.
    It does not exploit anything and does not require findings to produce value.
    """

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    TECH_PATTERNS = [
        ("WordPress", "CMS", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
        ("Drupal", "CMS", re.compile(r"drupal|/sites/default/", re.I)),
        ("Joomla", "CMS", re.compile(r"joomla|/media/system/js/", re.I)),
        ("Magento", "Ecommerce", re.compile(r"magento|mage/cookies", re.I)),
        ("Shopify", "Ecommerce", re.compile(r"cdn.shopify|shopify", re.I)),
        ("Next.js", "Frontend", re.compile(r"/_next/static|next-head-count", re.I)),
        ("React", "Frontend", re.compile(r"react|data-reactroot|__REACT", re.I)),
        ("Vue.js", "Frontend", re.compile(r"vue(?:\.min)?\.js|data-v-", re.I)),
        ("Angular", "Frontend", re.compile(r"ng-app|angular(?:\.min)?\.js|ng-version", re.I)),
        ("jQuery", "Frontend", re.compile(r"jquery(?:\.min)?\.js|jQuery", re.I)),
        ("Bootstrap", "Frontend", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)),
        ("Firebase", "Cloud/App Platform", re.compile(r"firebaseapp|firebaseio|firebase", re.I)),
        ("Supabase", "Cloud/App Platform", re.compile(r"supabase", re.I)),
    ]

    SERVER_PATTERNS = [
        ("nginx", "Web Server", re.compile(r"nginx/?([0-9.]+)?", re.I)),
        ("Apache HTTP Server", "Web Server", re.compile(r"apache/?([0-9.]+)?", re.I)),
        ("Microsoft IIS", "Web Server", re.compile(r"microsoft-iis/?([0-9.]+)?", re.I)),
        ("LiteSpeed", "Web Server", re.compile(r"litespeed", re.I)),
        ("OpenResty", "Web Server", re.compile(r"openresty/?([0-9.]+)?", re.I)),
    ]

    WAF_CDN_MARKERS = [
        ("Cloudflare", "CDN/WAF", ["cf-ray", "cf-cache-status", "server: cloudflare"]),
        ("Akamai", "CDN/WAF", ["akamai", "x-akamai", "akamai-grn"]),
        ("AWS CloudFront", "CDN", ["cloudfront", "x-amz-cf", "x-cache"]),
        ("Sucuri", "WAF", ["x-sucuri-id", "sucuri"]),
        ("Fastly", "CDN/WAF", ["fastly", "x-served-by", "x-cache-hits"]),
        ("Imperva", "WAF", ["incap_ses", "x-iinfo", "imperva"]),
        ("Vercel", "Hosting", ["x-vercel", "server: vercel"]),
        ("Netlify", "Hosting", ["x-nf-request-id", "server: netlify"]),
    ]

    def __init__(self, *, state: Any, client: Any, dashboard: Any | None = None, advisory_lookup: bool = True, max_advisories: int = 25) -> None:
        self.state = state
        self.client = client
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.host = getattr(state, "host", urlparse(self.target).hostname or "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.advisory_lookup = advisory_lookup and os.getenv("VULNSCOPE_DISABLE_CVE_LOOKUP", "0") != "1"
        self.max_advisories = max(1, int(max_advisories))
        self.technologies: list[TechnologyFinding] = []
        self.advisories: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str, evidence: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Technology Intelligence", phase_progress=24, current_agent="TechnologyIntelAgent", current_tool="technology_intelligence", action=action, endpoint=self.target, evidence=evidence[:1000], safety_status="passive fingerprinting • public advisory lookup • no exploitation")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def add_tech(self, name: str, category: str, evidence: str, confidence: int = 70, version: str = "") -> None:
        key = (name.lower(), category.lower(), version)
        for item in self.technologies:
            if (item.name.lower(), item.category.lower(), item.version) == key:
                return
        self.technologies.append(TechnologyFinding(name=name, category=category, evidence=evidence[:500], confidence=max(0, min(100, confidence)), version=version[:80]))

    def root_response(self) -> Any | None:
        self.dash("Fetching root page for passive technology fingerprinting")
        try:
            return self.client.get(self.target, purpose="technology-intelligence-root")
        except Exception as exc:
            self.errors.append({"stage": "root_fetch", "error": str(exc)[:500]})
            return None

    def fingerprint_headers(self, response: Any) -> None:
        headers = {str(k): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if server:
            matched = False
            for name, category, pattern in self.SERVER_PATTERNS:
                match = pattern.search(server)
                if match:
                    self.add_tech(name, category, f"Server header: {server}", 85, version=(match.group(1) or "") if match.groups() else "")
                    matched = True
            if not matched:
                self.add_tech(server.split()[0], "Web Server", f"Server header: {server}", 65)
        if powered:
            self.add_tech(powered.split()[0], "Runtime", f"X-Powered-By header: {powered}", 80)
        low_blob = header_blob.lower()
        for name, category, markers in self.WAF_CDN_MARKERS:
            if any(marker.lower() in low_blob for marker in markers):
                self.add_tech(name, category, "Header marker matched: " + ", ".join(markers), 80)
        missing = [name for name in self.SECURITY_HEADERS if name not in headers]
        present = [name for name in self.SECURITY_HEADERS if name in headers]
        self.notes.append(f"Security headers present={len(present)} missing={len(missing)}")
        if missing:
            self.notes.append("Missing security headers: " + ", ".join(missing))

    def fingerprint_body(self, response: Any) -> None:
        text = getattr(response, "text", "") or ""
        if not text:
            return
        sample = text[:250000]
        for name, category, pattern in self.TECH_PATTERNS:
            if pattern.search(sample):
                self.add_tech(name, category, "Body/script marker matched", 70)
        try:
            soup = BeautifulSoup(sample, "html.parser")
            generator = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
            if generator and generator.get("content"):
                content = str(generator.get("content"))
                self.add_tech(content.split()[0], "Generator", f"meta generator: {content}", 85)
            for script in soup.find_all("script", src=True)[:120]:
                src = str(script.get("src") or "")
                for name, category, pattern in self.TECH_PATTERNS:
                    if pattern.search(src):
                        self.add_tech(name, category, f"script src: {src}", 78)
            for link in soup.find_all("link", href=True)[:120]:
                href = str(link.get("href") or "")
                for name, category, pattern in self.TECH_PATTERNS:
                    if pattern.search(href):
                        self.add_tech(name, category, f"link href: {href}", 74)
        except Exception as exc:
            self.errors.append({"stage": "body_parse", "error": str(exc)[:500]})

    def tls_snapshot(self) -> dict[str, Any]:
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            return {"enabled": False, "reason": "target scheme is not https"}
        self.dash("Collecting TLS certificate metadata")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    return {"enabled": True, "issuer": cert.get("issuer", []), "subject": cert.get("subject", []), "notBefore": cert.get("notBefore", ""), "notAfter": cert.get("notAfter", ""), "cipher": cipher}
        except Exception as exc:
            self.errors.append({"stage": "tls", "error": str(exc)[:500]})
            return {"enabled": False, "error": str(exc)[:500]}

    def dns_snapshot(self) -> dict[str, Any]:
        self.dash("Collecting DNS resolution snapshot")
        try:
            host, aliases, addresses = socket.gethostbyname_ex(self.host)
            return {"host": host, "aliases": aliases, "addresses": addresses}
        except Exception as exc:
            self.errors.append({"stage": "dns", "error": str(exc)[:500]})
            return {"error": str(exc)[:500]}

    def advisory_keywords(self) -> list[str]:
        keywords = []
        for item in self.technologies:
            name = item.name.strip()
            if not name or len(name) < 3:
                continue
            if name.lower() in {"cloudflare", "akamai", "fastly", "vercel", "netlify"}:
                continue
            keywords.append((name + " " + item.version).strip())
        return list(dict.fromkeys(keywords))[:8]

    def lookup_nvd(self, keyword: str) -> list[dict[str, Any]]:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        try:
            response = requests.get(url, params={"keywordSearch": keyword, "resultsPerPage": 5}, timeout=8, headers={"User-Agent": "VulnScope-Advisory-Mapper/1.0"})
            if response.status_code != 200:
                return []
            data = response.json()
            rows = []
            for item in data.get("vulnerabilities", [])[:5]:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                score = None
                severity = "UNKNOWN"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metric_rows = metrics.get(key) or []
                    if metric_rows:
                        cvss = metric_rows[0].get("cvssData", {})
                        score = cvss.get("baseScore")
                        severity = metric_rows[0].get("baseSeverity") or cvss.get("baseSeverity") or severity
                        break
                descriptions = cve.get("descriptions", [])
                desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
                rows.append({"source": "NVD", "keyword": keyword, "id": cve.get("id", ""), "published": cve.get("published", ""), "lastModified": cve.get("lastModified", ""), "severity": severity, "score": score, "description": desc[:700], "url": "https://nvd.nist.gov/vuln/detail/" + cve.get("id", "")})
            return rows
        except Exception as exc:
            self.errors.append({"stage": "nvd_lookup", "keyword": keyword, "error": str(exc)[:500]})
            return []

    def lookup_advisories(self) -> None:
        if not self.advisory_lookup:
            self.notes.append("Advisory lookup disabled by configuration.")
            return
        for keyword in self.advisory_keywords():
            self.dash("Checking public advisories for " + keyword)
            for row in self.lookup_nvd(keyword):
                self.advisories.append(row)
                if len(self.advisories) >= self.max_advisories:
                    return

    def write_reports(self, tls: dict[str, Any], dns: dict[str, Any]) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "host": self.host, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "technologies": [asdict(item) for item in self.technologies], "tls": tls, "dns": dns, "advisories": self.advisories, "notes": self.notes, "errors": self.errors, "method": "passive fingerprinting plus public advisory lookup"}
        json_path = self.out_dir / "technology-intelligence.json"
        md_path = self.out_dir / "technology-intelligence.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        lines = ["# Technology Intelligence Report", "", f"Target: `{self.target}`", f"Host: `{self.host}`", "", "## Detected Technologies", ""]
        if not self.technologies:
            lines.append("No high-confidence technology fingerprints were detected from passive evidence.")
        else:
            for item in self.technologies:
                version = f" version=`{item.version}`" if item.version else ""
                lines.append(f"- **{item.name}** category=`{item.category}` confidence=`{item.confidence}`{version} evidence={item.evidence}")
        lines.extend(["", "## TLS", "", "```json", json.dumps(tls, indent=2, default=str)[:4000], "```", "", "## DNS", "", "```json", json.dumps(dns, indent=2, default=str)[:4000], "```", "", "## Public Advisory Leads", ""])
        if not self.advisories:
            lines.append("No public advisory leads were collected, or lookup was unavailable/disabled.")
        else:
            for row in self.advisories[: self.max_advisories]:
                lines.append(f"- `{row.get('id')}` keyword=`{row.get('keyword')}` severity=`{row.get('severity')}` score=`{row.get('score')}` published=`{row.get('published')}` {row.get('url')}")
        lines.extend(["", "## Notes", ""])
        for note in self.notes:
            lines.append("- " + note)
        if self.errors:
            lines.extend(["", "## Non-Fatal Errors", ""])
            for err in self.errors[:20]:
                lines.append("- " + json.dumps(err, ensure_ascii=False))
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"technology_intelligence_json": str(json_path), "technology_intelligence_md": str(md_path)}

    def run(self) -> dict[str, Any]:
        response = self.root_response()
        if response is not None and getattr(response, "received", False):
            self.fingerprint_headers(response)
            self.fingerprint_body(response)
        tls = self.tls_snapshot()
        dns = self.dns_snapshot()
        self.lookup_advisories()
        reports = self.write_reports(tls, dns)
        try:
            self.state.stats["technology_count"] = len(self.technologies)
            self.state.stats["advisory_count"] = len(self.advisories)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "technologies": len(self.technologies), "advisories": len(self.advisories), "reports": reports, "errors": len(self.errors)}
