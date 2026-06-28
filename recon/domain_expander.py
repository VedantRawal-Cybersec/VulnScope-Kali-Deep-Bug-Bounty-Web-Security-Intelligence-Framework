from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests

OUT_DIR = Path("reports/output/recon")


@dataclass
class ReconResult:
    root_domain: str
    subdomains: list[str]
    archived_urls: list[str]
    high_value_urls: list[dict]
    notes: list[str]


def normalize_domain(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    host = urlparse(value).netloc.split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def run_passive_domain_expansion(target: str, include_external_tools: bool = True, max_urls: int = 5000) -> ReconResult:
    domain = normalize_domain(target)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    subdomains = set()
    archived_urls = set()

    for item in _from_crtsh(domain, notes):
        subdomains.add(item)
    if include_external_tools:
        for item in _run_subfinder(domain, notes):
            subdomains.add(item)
        for item in _run_gau(domain, notes):
            archived_urls.add(item)
        for item in _run_waybackurls(domain, notes):
            archived_urls.add(item)

    # Add conservative fallback URLs for discovered hosts.
    for host in list(subdomains)[:500]:
        archived_urls.add(f"https://{host}/")

    clean_subdomains = sorted(_same_root_hosts(subdomains, domain))
    clean_urls = sorted(url for url in archived_urls if _url_host_in_scope(url, domain))[:max_urls]
    high_value = classify_high_value_urls(clean_urls)
    result = ReconResult(domain, clean_subdomains, clean_urls, high_value, notes)
    _write_outputs(result)
    return result


def classify_high_value_urls(urls: list[str]) -> list[dict]:
    signals = []
    patterns = [
        ("api_route", re.compile(r"/api/|/graphql|/v[0-9]+/", re.I), "API or GraphQL route candidate"),
        ("auth_route", re.compile(r"login|logout|oauth|sso|callback|token|session", re.I), "Authentication/session flow candidate"),
        ("admin_route", re.compile(r"admin|dashboard|manage|console|internal", re.I), "Administrative or internal-sounding route"),
        ("object_route", re.compile(r"/(order|account|user|invoice|booking|ticket|profile|cart|payment)s?/", re.I), "Object or account-bound workflow route"),
        ("file_route", re.compile(r"\.(js|map|json|xml|yml|yaml|env|bak|old|zip|sql)(\?|$)", re.I), "Interesting file extension or archived asset"),
        ("redirect_param", re.compile(r"[?&](url|redirect|next|return|continue|callback)=", re.I), "Redirect/state parameter candidate"),
        ("id_param", re.compile(r"[?&](id|user_id|account_id|order_id|invoice_id|uid)=", re.I), "Identifier parameter candidate"),
    ]
    for url in urls:
        matched = []
        for key, pattern, reason in patterns:
            if pattern.search(url):
                matched.append({"signal": key, "reason": reason})
        if matched:
            signals.append({"url": url, "signals": matched, "status": "REVIEW_CANDIDATE"})
    return signals[:1000]


def _from_crtsh(domain: str, notes: list[str]) -> set[str]:
    results = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=20, headers={"User-Agent": "VulnScope passive recon"})
        if response.status_code != 200:
            notes.append(f"crt.sh returned HTTP {response.status_code}")
            return results
        for row in response.json():
            name = str(row.get("name_value", ""))
            for item in name.split("\n"):
                item = item.strip().lower().lstrip("*.")
                if item.endswith(domain):
                    results.add(item)
    except Exception as exc:
        notes.append(f"crt.sh lookup failed: {exc}")
    return results


def _run_subfinder(domain: str, notes: list[str]) -> set[str]:
    if not shutil.which("subfinder"):
        notes.append("subfinder not installed")
        return set()
    return _run_lines(["subfinder", "-d", domain, "-silent"], notes, "subfinder")


def _run_gau(domain: str, notes: list[str]) -> set[str]:
    if not shutil.which("gau"):
        notes.append("gau not installed")
        return set()
    return _run_lines(["gau", domain], notes, "gau")


def _run_waybackurls(domain: str, notes: list[str]) -> set[str]:
    if not shutil.which("waybackurls"):
        notes.append("waybackurls not installed")
        return set()
    try:
        proc = subprocess.run(["bash", "-lc", f"echo {domain} | waybackurls"], text=True, capture_output=True, timeout=120)
        if proc.returncode != 0:
            notes.append(f"waybackurls exited {proc.returncode}: {proc.stderr[:200]}")
        return {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    except Exception as exc:
        notes.append(f"waybackurls failed: {exc}")
        return set()


def _run_lines(command: list[str], notes: list[str], label: str) -> set[str]:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=120)
        if proc.returncode != 0:
            notes.append(f"{label} exited {proc.returncode}: {proc.stderr[:200]}")
        return {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    except Exception as exc:
        notes.append(f"{label} failed: {exc}")
        return set()


def _same_root_hosts(hosts: set[str], domain: str) -> set[str]:
    return {host.lower().strip().lstrip("*.") for host in hosts if host.lower().strip().lstrip("*.").endswith(domain)}


def _url_host_in_scope(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).netloc.split(":")[0].lower()
        return host == domain or host.endswith("." + domain)
    except Exception:
        return False


def _write_outputs(result: ReconResult) -> None:
    data = {
        "root_domain": result.root_domain,
        "subdomain_count": len(result.subdomains),
        "archived_url_count": len(result.archived_urls),
        "high_value_count": len(result.high_value_urls),
        "subdomains": result.subdomains,
        "archived_urls": result.archived_urls,
        "high_value_urls": result.high_value_urls,
        "notes": result.notes,
        "safety": "Passive expansion only. Active testing of subdomains requires explicit authorization and approval.",
    }
    (OUT_DIR / "domain-expansion.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT_DIR / "subdomains.txt").write_text("\n".join(result.subdomains), encoding="utf-8")
    (OUT_DIR / "archived-urls.txt").write_text("\n".join(result.archived_urls), encoding="utf-8")
    (OUT_DIR / "high-value-urls.json").write_text(json.dumps(result.high_value_urls, indent=2, ensure_ascii=False), encoding="utf-8")
    md = ["# Passive Domain Expansion Report", "", f"Root domain: `{result.root_domain}`", f"Subdomains: **{len(result.subdomains)}**", f"Archived URLs: **{len(result.archived_urls)}**", f"High-value URL candidates: **{len(result.high_value_urls)}**", "", "## High-Value URL Candidates", ""]
    for item in result.high_value_urls[:100]:
        reasons = ", ".join(signal["signal"] for signal in item.get("signals", []))
        md.append(f"- `{item['url']}` — {reasons}")
    if result.notes:
        md += ["", "## Notes", ""] + [f"- {note}" for note in result.notes]
    (OUT_DIR / "domain-expansion.md").write_text("\n".join(md), encoding="utf-8")
