from __future__ import annotations

import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlencode, urlparse
from urllib.request import Request, urlopen

OUT = Path("reports/output/artemis/recon")
COMMON_SUBS = [
    "www", "api", "app", "admin", "login", "dashboard", "portal", "dev", "test", "staging",
    "beta", "cdn", "static", "assets", "mail", "smtp", "vpn", "sso", "auth", "graphql",
]
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)


def domain_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return parsed.netloc.split(":")[0].lower().strip()


def fetch_json(url: str, timeout: int = 20) -> Any:
    req = Request(url, headers={"User-Agent": "VulnScope-ARTEMIS-PASSIVE/1.0"})
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="ignore"))


def fetch_text(url: str, timeout: int = 20) -> str:
    req = Request(url, headers={"User-Agent": "VulnScope-ARTEMIS-PASSIVE/1.0"})
    with urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def dns_guess(domain: str) -> list[dict[str, Any]]:
    out = []
    for sub in COMMON_SUBS:
        host = f"{sub}.{domain}"
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({item[4][0] for item in infos})
            if ips:
                out.append({"host": host, "ips": ips, "source": "dns_guess"})
        except Exception:
            continue
    return out


def crtsh(domain: str, max_records: int = 500) -> list[dict[str, Any]]:
    try:
        data = fetch_json(f"https://crt.sh/?q=%25.{quote_plus(domain)}&output=json")
    except Exception as exc:
        return [{"error": str(exc), "source": "crtsh"}]
    seen = set()
    rows = []
    for item in data[:max_records] if isinstance(data, list) else []:
        names = str(item.get("name_value", "")).splitlines()
        for name in names:
            clean = name.strip().lstrip("*.").lower()
            if clean.endswith(domain) and clean not in seen:
                seen.add(clean)
                rows.append({"host": clean, "source": "crtsh"})
    return rows


def wayback_urls(domain: str, max_records: int = 500) -> list[str]:
    url = "https://web.archive.org/cdx?" + urlencode({
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(max_records),
    })
    try:
        data = fetch_json(url, timeout=30)
    except Exception:
        return []
    urls = []
    if isinstance(data, list):
        for row in data[1:]:
            if isinstance(row, list) and row and isinstance(row[0], str):
                urls.append(row[0])
    return sorted(set(urls))


def security_txt(domain: str) -> dict[str, Any]:
    candidates = [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"]
    for url in candidates:
        try:
            text = fetch_text(url, timeout=10)
            return {"url": url, "found": True, "preview": text[:2000]}
        except Exception:
            continue
    return {"found": False}


def public_google(domain: str, limit: int = 5) -> dict[str, Any]:
    try:
        from aegis.google_intelligence_safe import run_google_intel
        return run_google_intel(domain, limit_per_query=limit)
    except Exception as exc:
        return {"configured": False, "error": str(exc), "candidates": []}


def run_passive_recon(target: str, google_limit: int = 5, max_public_records: int = 500) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    domain = domain_from_target(target)
    crt = crtsh(domain, max_records=max_public_records)
    dns = dns_guess(domain)
    wayback = wayback_urls(domain, max_records=max_public_records)
    sec = security_txt(domain)
    goog = public_google(domain, google_limit)
    hosts = sorted({r.get("host") for r in crt + dns if isinstance(r, dict) and r.get("host")})
    endpoints = sorted(set(wayback))
    intel = {
        "target": target,
        "domain": domain,
        "generated_at": time.time(),
        "mode": "passive_only",
        "summary": {"hosts": len(hosts), "wayback_urls": len(endpoints), "google_candidates": len(goog.get("candidates", [])) if isinstance(goog, dict) else 0, "security_txt": bool(sec.get("found"))},
        "hosts": hosts,
        "dns_guess": dns,
        "crtsh": crt,
        "wayback_urls": endpoints,
        "security_txt": sec,
        "google_intel": goog,
    }
    safe_name = domain.replace("/", "_")
    (OUT / f"{safe_name}-passive-recon.json").write_text(json.dumps(intel, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# ARTEMIS Passive Recon — {domain}", "", f"Hosts: `{len(hosts)}`", f"Wayback URLs: `{len(endpoints)}`", f"Google candidates: `{intel['summary']['google_candidates']}`", f"security.txt: `{sec.get('found')}`", "", "## Hosts"]
    for h in hosts[:100]:
        lines.append(f"- `{h}`")
    lines += ["", "## High-Signal URLs"]
    for u in endpoints[:100]:
        if any(x in u.lower() for x in ["api", "admin", "login", "graphql", "id=", "user", "order", "invoice", "redirect"]):
            lines.append(f"- `{u}`")
    (OUT / f"{safe_name}-passive-recon.md").write_text("\n".join(lines), encoding="utf-8")
    return intel
