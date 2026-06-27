from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import RequestEngine
from core.scope_guard import is_same_domain


def analyze_robots_and_sitemap(
    base_url: str,
    target_host: str,
    request_engine: RequestEngine,
    store: EvidenceStore,
) -> None:
    robots_url = urljoin(base_url + "/", "robots.txt")
    robots_response = request_engine.get(robots_url)

    disallowed: list[str] = []
    sitemap_urls: list[str] = []

    if robots_response.status_code == 200 and robots_response.text:
        for line in robots_response.text.splitlines():
            cleaned = line.strip()
            if cleaned.lower().startswith("disallow:"):
                value = cleaned.split(":", 1)[1].strip()
                if value:
                    disallowed.append(value)
                    endpoint = urljoin(base_url + "/", value.lstrip("/"))
                    if is_same_domain(endpoint, target_host):
                        store.add_endpoint(endpoint)
            elif cleaned.lower().startswith("sitemap:"):
                value = cleaned.split(":", 1)[1].strip()
                if value:
                    sitemap_urls.append(value)

    common_sitemaps = [urljoin(base_url + "/", "sitemap.xml")]
    for sitemap_url in sitemap_urls + common_sitemaps:
        _parse_sitemap(sitemap_url, target_host, request_engine, store)

    if disallowed or sitemap_urls:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="robots.txt and Sitemap Intelligence Collected",
                category="Attack Surface Discovery",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint=robots_url,
                where_found="robots.txt and sitemap.xml analysis",
                how_detected=["robots.txt directives and sitemap references were parsed for same-domain routes"],
                why_risky="This is not a vulnerability. robots.txt and sitemap files can reveal application areas that should be included in authorized manual review.",
                evidence={
                    "robots_url": robots_url,
                    "disallow_count": len(disallowed),
                    "disallow_sample": disallowed[:20],
                    "sitemap_urls": sitemap_urls[:10],
                },
                recommended_validation=["Review discovered routes for authorization and sensitive-data exposure within scope."],
                remediation=["Do not rely on robots.txt as an access-control mechanism. Enforce server-side authorization."],
            )
        )


def _parse_sitemap(
    sitemap_url: str,
    target_host: str,
    request_engine: RequestEngine,
    store: EvidenceStore,
) -> None:
    response = request_engine.get(sitemap_url)
    if response.status_code != 200 or not response.text:
        return

    urls: list[str] = []
    try:
        root = ET.fromstring(response.text.encode("utf-8"))
        for element in root.iter():
            if element.tag.lower().endswith("loc") and element.text:
                urls.append(element.text.strip())
    except ET.ParseError:
        urls = re.findall(r"https?://[^<\s]+", response.text)

    added = 0
    for url in urls:
        if is_same_domain(url, target_host):
            store.add_endpoint(url)
            added += 1

    if added:
        store.metadata.setdefault("sitemap_intelligence", []).append(
            {"sitemap_url": sitemap_url, "same_domain_urls_added": added}
        )
