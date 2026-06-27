from __future__ import annotations

from collections import deque
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from core.evidence_store import EvidenceStore
from core.request_engine import RequestEngine, ResponseRecord
from core.scope_guard import is_same_domain, normalize_link


def crawl_same_domain(
    start_url: str,
    target_host: str,
    request_engine: RequestEngine,
    store: EvidenceStore,
    max_pages: int = 30,
) -> list[ResponseRecord]:
    visited: set[str] = set()
    queue: deque[str] = deque([start_url])
    responses: list[ResponseRecord] = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        if not is_same_domain(url, target_host):
            continue

        visited.add(url)
        store.add_endpoint(url)
        response = request_engine.get(url)
        responses.append(response)

        if response.error or not response.text:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(["a", "link", "script"]):
            href = tag.get("href") or tag.get("src")
            normalized = normalize_link(response.url, href)
            if normalized and is_same_domain(normalized, target_host):
                store.add_endpoint(normalized)
                if _looks_like_html_route(normalized) and normalized not in visited:
                    queue.append(normalized)

        _extract_forms(response.url, soup, store)
        _extract_url_parameters(response.url, store)

    return responses


def _looks_like_html_route(url: str) -> bool:
    path = urlparse(url).path.lower()
    blocked_ext = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".css",
        ".ico",
        ".pdf",
        ".zip",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )
    return not path.endswith(blocked_ext)


def _extract_forms(page_url: str, soup: BeautifulSoup, store: EvidenceStore) -> None:
    for index, form in enumerate(soup.find_all("form"), start=1):
        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name:
                inputs.append(name)
        store.add_form(
            {
                "page_url": page_url,
                "form_index": index,
                "method": (form.get("method") or "GET").upper(),
                "action": form.get("action") or page_url,
                "inputs": sorted(set(inputs)),
            }
        )
        for param in inputs:
            store.add_parameter(page_url, param)


def _extract_url_parameters(url: str, store: EvidenceStore) -> None:
    parsed = urlparse(url)
    if not parsed.query:
        return
    for pair in parsed.query.split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0]
        if name:
            store.add_parameter(url, name)
