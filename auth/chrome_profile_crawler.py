from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urljoin, urlparse

from auth.playwright_login import playwright_available

DEFAULT_PROFILE_ROOT = Path.home() / ".vulnscope" / "google_profiles"
OUTPUT_DIR = Path("reports/output/auth")


@dataclass
class ChromeProfileCrawlConfig:
    label: str
    user_data_dir: str
    target_url: str
    max_pages: int = 10
    headless: bool = False
    delay_seconds: float = 0.8
    same_origin_only: bool = True
    capture_text: bool = True
    capture_links: bool = True


def _chrome_channel() -> str | None:
    if shutil.which("google-chrome") or shutil.which("google-chrome-stable"):
        return "chrome"
    if shutil.which("chromium") or shutil.which("chromium-browser"):
        return "chromium"
    return None


def _default_user_data_dir(account: str) -> Path:
    return DEFAULT_PROFILE_ROOT / account


def _safe_account_name(account: str) -> str:
    return "".join(c for c in account if c.isalnum() or c in {"_", "-"}) or "account"


def crawl_with_chrome_profile(
    account: str,
    target_url: str,
    user_data_dir: str | Path | None = None,
    max_pages: int = 10,
    headless: bool = False,
    delay_seconds: float = 0.8,
) -> dict:
    """Use an existing local Chrome profile for authorized authenticated review.

    This function never asks for Google credentials and never extracts passwords.
    It reuses a local browser profile that the user already logged into manually.
    It stays same-origin and only performs page navigation/link collection.
    """
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright")

    from playwright.sync_api import sync_playwright

    profile_dir = Path(user_data_dir) if user_data_dir else _default_user_data_dir(account)
    if not profile_dir.exists():
        raise FileNotFoundError(f"Chrome profile folder not found: {profile_dir}")

    parsed_base = urlparse(target_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        raise ValueError("target_url must be a full URL, e.g. https://example.com")
    host = parsed_base.netloc

    visited: set[str] = set()
    queue = [target_url]
    pages: list[dict] = []
    requests: list[dict] = []

    config = ChromeProfileCrawlConfig(
        label=account,
        user_data_dir=str(profile_dir),
        target_url=target_url,
        max_pages=max_pages,
        headless=headless,
        delay_seconds=delay_seconds,
    )

    with sync_playwright() as p:
        channel = _chrome_channel()
        kwargs = {
            "user_data_dir": str(profile_dir),
            "headless": headless,
            "viewport": {"width": 1400, "height": 900},
        }
        if channel:
            kwargs["channel"] = channel
        context = p.chromium.launch_persistent_context(**kwargs)
        page = context.pages[0] if context.pages else context.new_page()

        def on_request(req):
            try:
                parsed = urlparse(req.url)
                if parsed.netloc == host:
                    requests.append({"method": req.method, "url": req.url, "resource_type": req.resource_type})
            except Exception:
                pass

        page.on("request", on_request)

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != host:
                continue
            visited.add(url)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                time.sleep(delay_seconds)
                title = page.title()
                current = page.url
                body_text = ""
                if config.capture_text:
                    try:
                        body_text = page.locator("body").inner_text(timeout=7000)[:5000] if page.locator("body").count() else ""
                    except Exception:
                        body_text = ""
                same_domain_links: list[str] = []
                if config.capture_links:
                    try:
                        links = page.eval_on_selector_all("a[href]", "els => els.map(a => a.href)")
                    except Exception:
                        links = []
                    for link in links:
                        absolute = urljoin(current, link)
                        if urlparse(absolute).netloc == host and absolute not in visited and len(queue) < max_pages * 4:
                            same_domain_links.append(absolute)
                            queue.append(absolute)
                pages.append({
                    "url": current,
                    "title": title,
                    "text_sample": body_text,
                    "links": same_domain_links[:80],
                })
            except Exception as exc:
                pages.append({"url": url, "error": str(exc)})

        context.storage_state(path=str(OUTPUT_DIR / f"chrome-profile-{_safe_account_name(account)}-state.json"))
        context.close()

    result = {
        "type": "chrome_profile_authenticated_crawl",
        "config": asdict(config),
        "page_count": len(pages),
        "request_count": len(requests),
        "pages": pages,
        "requests": requests[:500],
        "safety": {
            "credentials_collected": False,
            "passwords_extracted": False,
            "same_origin_only": True,
            "state_changing_actions": False,
        },
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUTPUT_DIR / f"auth-crawl-{_safe_account_name(account)}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def compare_chrome_profile_crawls(account_a: str = "account_a", account_b: str = "account_b") -> dict:
    a_path = OUTPUT_DIR / f"auth-crawl-{_safe_account_name(account_a)}.json"
    b_path = OUTPUT_DIR / f"auth-crawl-{_safe_account_name(account_b)}.json"
    if not a_path.exists() or not b_path.exists():
        raise FileNotFoundError("Both account crawl outputs are required before comparison")
    a = json.loads(a_path.read_text(encoding="utf-8"))
    b = json.loads(b_path.read_text(encoding="utf-8"))
    a_urls = {p.get("url") for p in a.get("pages", []) if p.get("url")}
    b_urls = {p.get("url") for p in b.get("pages", []) if p.get("url")}
    result = {
        "account_a": account_a,
        "account_b": account_b,
        "only_account_a_urls": sorted(a_urls - b_urls),
        "only_account_b_urls": sorted(b_urls - a_urls),
        "common_urls": sorted(a_urls & b_urls),
        "review_notes": [
            "Differences are access-control review candidates, not confirmed vulnerabilities.",
            "Manually validate any URL visible to one account but not the other.",
            "Do not perform destructive actions unless explicitly authorized in scope.",
        ],
    }
    out = OUTPUT_DIR / "chrome-profile-account-comparison.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    md = OUTPUT_DIR / "chrome-profile-account-comparison.md"
    md.write_text(_comparison_markdown(result), encoding="utf-8")
    return result


def _comparison_markdown(result: dict) -> str:
    lines = ["# Chrome Profile Account Comparison", ""]
    lines.append(f"Account A: `{result['account_a']}`")
    lines.append(f"Account B: `{result['account_b']}`")
    lines.append("")
    for key, title in [
        ("only_account_a_urls", "Only Account A URLs"),
        ("only_account_b_urls", "Only Account B URLs"),
        ("common_urls", "Common URLs"),
    ]:
        lines.append(f"## {title}")
        urls = result.get(key, [])
        if not urls:
            lines.append("- None")
        else:
            for url in urls[:100]:
                lines.append(f"- {url}")
        lines.append("")
    lines.append("## Review Notes")
    for note in result.get("review_notes", []):
        lines.append(f"- {note}")
    return "\n".join(lines) + "\n"
