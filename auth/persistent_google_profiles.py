from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from auth.credential_store import AuthProfile
from auth.playwright_login import playwright_available

PERSISTENT_ROOT = Path.home() / ".vulnscope" / "browser_profiles"
STATE_DIR = Path("reports/output/auth/states")


@dataclass
class PersistentGoogleProfile:
    profile_name: str
    account_label: str
    email_label: str
    target_url: str
    login_url: str
    user_data_dir: str
    storage_state: str
    notes: str = "Persistent local browser profile. No Google password is stored by VulnScope."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def profile_dir(profile_name: str, account_label: str) -> Path:
    safe_profile = "".join(c for c in profile_name if c.isalnum() or c in {"-", "_"}) or "default"
    safe_account = "".join(c for c in account_label if c.isalnum() or c in {"-", "_"}) or "account"
    return PERSISTENT_ROOT / safe_profile / safe_account


def metadata_path(profile_name: str) -> Path:
    return PERSISTENT_ROOT / profile_name / "persistent_profiles.json"


def save_metadata(record: PersistentGoogleProfile) -> None:
    PERSISTENT_ROOT.mkdir(parents=True, exist_ok=True)
    path = metadata_path(record.profile_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data[record.account_label] = record.to_dict()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def load_metadata(profile_name: str) -> dict[str, Any]:
    path = metadata_path(profile_name)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def persistent_state_path(profile_name: str, account_label: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"{profile_name}-{account_label}-persistent-google.json"


def ensure_persistent_google_profile(profile: AuthProfile, account_label: str, oauth_url: str | None = None, headless: bool = False) -> Path:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")
    from playwright.sync_api import sync_playwright

    account = profile.account_a if account_label == "account_a" else profile.account_b
    if account is None:
        raise ValueError(f"Account not configured: {account_label}")

    PERSISTENT_ROOT.mkdir(parents=True, exist_ok=True)
    user_dir = profile_dir(profile.name, account_label)
    user_dir.mkdir(parents=True, exist_ok=True)
    state_path = persistent_state_path(profile.name, account_label)
    start_url = oauth_url or profile.login_url or profile.target_url

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(user_dir),
            headless=headless,
            viewport={"width": 1400, "height": 900},
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        print("\n┌──────────── Persistent Google Profile Login ────────────┐")
        print("│ Login manually in the opened browser window.             │")
        print("│ VulnScope stores local Chromium profile data only.       │")
        print("│ No Google password is requested or stored by VulnScope.  │")
        print("│ Sessions can expire if Google or the target invalidates. │")
        print("└──────────────────────────────────────────────────────────┘")
        print(f"Profile     : {profile.name}")
        print(f"Account     : {account_label} / {account.username}")
        print(f"Start URL   : {start_url}")
        print(f"Profile dir : {user_dir}")
        input("Press Enter after login is complete and the target app is authenticated...")
        context.storage_state(path=str(state_path))
        context.close()

    record = PersistentGoogleProfile(
        profile_name=profile.name,
        account_label=account_label,
        email_label=account.username,
        target_url=profile.target_url,
        login_url=profile.login_url,
        user_data_dir=str(user_dir),
        storage_state=str(state_path),
    )
    save_metadata(record)
    return state_path


def open_persistent_profile(profile: AuthProfile, account_label: str, url: str | None = None, headless: bool = False) -> None:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")
    from playwright.sync_api import sync_playwright

    user_dir = profile_dir(profile.name, account_label)
    if not user_dir.exists():
        raise FileNotFoundError(f"Persistent browser profile not found: {user_dir}. Run --persistent-google-login first.")
    start_url = url or profile.target_url
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(str(user_dir), headless=headless, viewport={"width": 1400, "height": 900})
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        print("\n[+] Persistent profile opened.")
        print(f"[+] URL: {page.url}")
        input("Press Enter to close the persistent browser profile...")
        context.storage_state(path=str(persistent_state_path(profile.name, account_label)))
        context.close()


def delete_persistent_profile(profile_name: str, account_label: str | None = None) -> Path:
    target = profile_dir(profile_name, account_label) if account_label else PERSISTENT_ROOT / profile_name
    if target.exists():
        shutil.rmtree(target)
    return target


def list_persistent_profiles(profile_name: str | None = None) -> dict[str, Any]:
    if profile_name:
        return {profile_name: load_metadata(profile_name)}
    out: dict[str, Any] = {}
    if not PERSISTENT_ROOT.exists():
        return out
    for child in PERSISTENT_ROOT.iterdir():
        if child.is_dir():
            out[child.name] = load_metadata(child.name)
    return out
