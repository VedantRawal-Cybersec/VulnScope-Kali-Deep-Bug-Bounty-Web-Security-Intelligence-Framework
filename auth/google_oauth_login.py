from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from auth.credential_store import AuthAccount, AuthProfile
from auth.playwright_login import playwright_available

STATE_DIR = Path("reports/output/auth/states")
GOOGLE_LOGIN_URL = "https://accounts.google.com/"


def is_google_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host == "accounts.google.com" or host.endswith(".accounts.google.com")


def save_google_oauth_state(
    profile: AuthProfile,
    account: AuthAccount,
    oauth_url: str | None = None,
    headless: bool = False,
) -> Path:
    """
    Opens a real browser for Google/OAuth login and saves only the authenticated browser state.

    Important: this function never asks for, stores, or autofills Google passwords.
    The user completes Google login directly inside the real browser page.
    """
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")

    from playwright.sync_api import sync_playwright

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_path = STATE_DIR / f"{profile.name}-{account.label}-google.json"
    start_url = oauth_url or profile.login_url or GOOGLE_LOGIN_URL

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)

        print("\n┌──────────────────── Google OAuth Login ────────────────────┐")
        print("│ Complete login directly inside the opened browser window.   │")
        print("│ The tool will not ask for or store the Google password.     │")
        print("│ OTP/CAPTCHA/MFA must be completed manually by the user.     │")
        print("└─────────────────────────────────────────────────────────────┘")
        print(f"Started URL : {start_url}")
        print(f"Current URL : {page.url}")
        if not is_google_url(page.url) and "google" not in page.url.lower():
            print("[!] Note: you may need to click 'Continue with Google' on the target login page.")
        input("Press Enter after Google login redirects back to the target application...")

        context.storage_state(path=str(state_path))
        browser.close()

    return state_path
