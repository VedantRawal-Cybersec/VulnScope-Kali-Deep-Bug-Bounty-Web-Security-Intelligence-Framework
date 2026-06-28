from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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
    def __init__(self, timeout: int = 30, delay: float = 0.4, retries: int = 2) -> None:
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            connect=retries,
            read=retries,
            status=retries,
            backoff_factor=1.2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) VulnScope-Kali/0.4 authorized-security-assessment",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            }
        )

    def get(self, url: str) -> ResponseRecord:
        time.sleep(self.delay)
        try:
            response = self.session.get(url, timeout=(10, self.timeout), allow_redirects=True)
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
        except requests.Timeout as exc:
            return self._error_response(url, f"Request timed out after {self.timeout}s read timeout. Increase --timeout or reduce --max-pages. Details: {exc}")
        except requests.RequestException as exc:
            return self._error_response(url, str(exc))

    @staticmethod
    def _error_response(url: str, error: str) -> ResponseRecord:
        return ResponseRecord(
            url=url,
            status_code=None,
            content_type="",
            content_length=0,
            title="",
            text="",
            headers={},
            cookies=[],
            error=error,
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
