from __future__ import annotations

from urllib.parse import urljoin, urlparse, urldefrag

from cai_scope_guard import cai_output_dir, host_from_target, is_allowed_host, normalize_target, scope_policy, slug_from_target


def normalize_link(base_url: str, href: str) -> str | None:
    if not href:
        return None
    href = href.strip()
    if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None
    absolute = urljoin(base_url, href)
    clean, _fragment = urldefrag(absolute)
    parsed = urlparse(clean)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return clean


def is_same_domain(url: str, target_host: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc.lower() == target_host.lower()


__all__ = [
    "normalize_link",
    "is_same_domain",
    "normalize_target",
    "host_from_target",
    "slug_from_target",
    "is_allowed_host",
    "scope_policy",
    "cai_output_dir",
]
