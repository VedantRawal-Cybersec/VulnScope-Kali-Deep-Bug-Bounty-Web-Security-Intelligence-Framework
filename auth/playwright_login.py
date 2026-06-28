from __future__ import annotations

import json
from pathlib import Path

from auth.credential_store import AuthAccount, AuthProfile

STATE_DIR = Path("reports/output/auth/states")


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def save_login_state(profile: AuthProfile, account: AuthAccount, headless: bool = False, manual_pause: bool = True) -> Path:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")

    from playwright.sync_api import sync_playwright

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_path = STATE_DIR / f"{profile.name}-{account.label}.json"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()
        page.goto(profile.login_url, wait_until="domcontentloaded", timeout=60000)

        # Best-effort credential fill. If selectors fail, user can complete login manually.
        _best_effort_fill(page, account.username, account.password)
        if manual_pause:
            print("\n[!] Complete login manually if needed, including OTP/CAPTCHA.")
            print("[!] Do not perform destructive actions. Stop at a normal logged-in dashboard page.")
            input("Press Enter after the account is logged in and stable...")

        context.storage_state(path=str(state_path))
        browser.close()

    return state_path


def _best_effort_fill(page, username: str, password: str) -> None:
    username_selectors = [
        "input[type='email']",
        "input[name='email']",
        "input[name='username']",
        "input[id*='email' i]",
        "input[id*='user' i]",
    ]
    password_selectors = ["input[type='password']", "input[name='password']", "input[id*='pass' i]"]
    for selector in username_selectors:
        try:
            if page.locator(selector).count() > 0:
                page.locator(selector).first.fill(username, timeout=2000)
                break
        except Exception:
            continue
    for selector in password_selectors:
        try:
            if page.locator(selector).count() > 0:
                page.locator(selector).first.fill(password, timeout=2000)
                break
        except Exception:
            continue
    submit_selectors = ["button[type='submit']", "input[type='submit']"]
    for selector in submit_selectors:
        try:
            if page.locator(selector).count() > 0:
                page.locator(selector).first.click(timeout=2000)
                page.wait_for_load_state("domcontentloaded", timeout=15000)
                break
        except Exception:
            continue


def read_state_summary(path: Path) -> dict:
    if not path.exists():
        return {"exists": False, "path": str(path)}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    return {
        "exists": True,
        "path": str(path),
        "cookies": len(data.get("cookies", [])),
        "origins": len(data.get("origins", [])),
    }
