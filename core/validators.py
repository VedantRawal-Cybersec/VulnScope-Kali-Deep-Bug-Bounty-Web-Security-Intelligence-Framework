from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass(frozen=True)
class Target:
    raw_url: str
    normalized_url: str
    scheme: str
    host: str
    base_url: str


class ValidationError(ValueError):
    pass


def validate_target_url(raw_url: str) -> Target:
    if not raw_url or not raw_url.strip():
        raise ValidationError("Target URL cannot be empty")

    candidate = raw_url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Only HTTP and HTTPS targets are supported")
    if not parsed.netloc:
        raise ValidationError("Target URL must include a valid host")

    normalized_path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme, parsed.netloc, normalized_path, "", parsed.query, ""))
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    return Target(
        raw_url=raw_url,
        normalized_url=normalized,
        scheme=parsed.scheme,
        host=parsed.netloc.lower(),
        base_url=base_url,
    )
