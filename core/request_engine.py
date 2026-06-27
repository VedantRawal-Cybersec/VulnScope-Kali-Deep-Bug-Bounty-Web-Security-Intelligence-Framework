from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class ResponseRecord:
    url: str
    status_code: int | None
    content_type: str
    content_length: int
    title: str
    text: str
    headers: dict
    cookies: list[dict]
    error: Optional[str] = None


class RequestEngine:
    def __init__(self, timeout: int = 10, delay: float = 0.4) -> None:
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "VulnScope-Kali/0.1 authorized-security-assessment",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def get(self, url: str) -> ResponseRecord:
        time.sleep(self.delay)
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            text = response.text if self._is_textual(response.headers.get("content-type", "")) else ""
            return ResponseRecord(
                url=response.url,
                status_code=response.status_code,
                content_type=response.headers.get("content-type", ""),
                content_length=len(response.content or b""),
                title=self._extract_title(text),
                text=text,
                headers=dict(response.headers),
                cookies=[
                    {
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "domain": cookie.domain,
                        "path": cookie.path,
                    }
                    for cookie in response.cookies
                ],
                error=None,
            )
        except requests.RequestException as exc:
            return ResponseRecord(
                url=url,
                status_code=None,
                content_type="",
                content_length=0,
                title="",
                text="",
                headers={},
                cookies=[],
                error=str(exc),
            )

    @staticmethod
    def _is_textual(content_type: str) -> bool:
        lowered = content_type.lower()
        return any(token in lowered for token in ["text", "html", "json", "xml", "javascript"])

    @staticmethod
    def _extract_title(text: str) -> str:
        lower = text.lower()
        start = lower.find("<title>")
        end = lower.find("</title>")
        if start != -1 and end != -1 and end > start:
            return text[start + 7 : end].strip()[:120]
        return ""
