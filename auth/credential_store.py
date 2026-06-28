from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

AUTH_DIR = Path.home() / ".vulnscope"
AUTH_FILE = AUTH_DIR / "auth_profiles.local.json"


@dataclass
class AuthAccount:
    label: str
    username: str
    password: str = ""


@dataclass
class AuthProfile:
    name: str
    target_url: str
    login_url: str
    account_a: AuthAccount
    account_b: AuthAccount | None = None
    notes: str = "Owned test accounts only. Never commit this file."


def setup_auth_profile() -> None:
    print("┌──────────────── Authenticated Validation Setup ────────────────┐")
    print("│ Credentials stay local in ~/.vulnscope/auth_profiles.local.json │")
    print("│ Use only owned test accounts and authorized targets.            │")
    print("└────────────────────────────────────────────────────────────────┘")
    name = input("Profile name [default]: ").strip() or "default"
    target_url = input("Target base URL: ").strip()
    login_url = input("Login URL: ").strip()
    account_a = AuthAccount(
        label="account_a",
        username=input("Account A username/email: ").strip(),
        password=getpass.getpass("Account A password: "),
    )
    add_b = input("Add Account B for comparison? yes/no: ").strip().lower() in {"yes", "y"}
    account_b = None
    if add_b:
        account_b = AuthAccount(
            label="account_b",
            username=input("Account B username/email: ").strip(),
            password=getpass.getpass("Account B password: "),
        )
    profile = AuthProfile(name=name, target_url=target_url, login_url=login_url, account_a=account_a, account_b=account_b)
    save_profile(profile)
    print(f"[+] Saved local auth profile: {name}")
    print(f"[+] Path: {AUTH_FILE}")


def setup_google_oauth_profile(
    name: str = "default",
    target_url: str | None = None,
    login_url: str | None = None,
    account_a_email: str | None = None,
    account_b_email: str | None = None,
    interactive: bool = True,
) -> AuthProfile:
    print("┌──────────── Google/OAuth Profile Setup ────────────┐")
    print("│ No Google password is requested or stored.          │")
    print("│ Browser login is completed manually by the user.    │")
    print("└─────────────────────────────────────────────────────┘")
    if interactive:
        name = input(f"Profile name [{name}]: ").strip() or name
        target_url = target_url or input("Target base URL, e.g. https://app.example.com: ").strip()
        login_url = login_url or input("Target login URL / Continue-with-Google page: ").strip()
        account_a_email = account_a_email or input("Account A email/label: ").strip()
        add_b = input("Add Account B for comparison? yes/no: ").strip().lower() in {"yes", "y"}
        if add_b:
            account_b_email = account_b_email or input("Account B email/label: ").strip()
    if not target_url or not login_url or not account_a_email:
        raise ValueError("target_url, login_url, and account_a_email are required for Google/OAuth profile setup")
    profile = AuthProfile(
        name=name,
        target_url=target_url,
        login_url=login_url,
        account_a=AuthAccount(label="account_a", username=account_a_email, password=""),
        account_b=AuthAccount(label="account_b", username=account_b_email, password="") if account_b_email else None,
        notes="Google/OAuth profile. No Google password stored. Browser session state is saved after manual login.",
    )
    save_profile(profile)
    print(f"[+] Saved Google/OAuth auth profile: {name}")
    print(f"[+] Path: {AUTH_FILE}")
    return profile


def save_profile(profile: AuthProfile) -> None:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    data = load_all_profiles(raw=True)
    data[profile.name] = asdict(profile)
    AUTH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(AUTH_FILE, 0o600)
    except Exception:
        pass


def load_all_profiles(raw: bool = False) -> dict[str, Any]:
    if not AUTH_FILE.exists():
        return {}
    try:
        return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_profile(name: str = "default") -> AuthProfile:
    data = load_all_profiles(raw=True)
    if name not in data:
        raise FileNotFoundError(f"Auth profile not found: {name}. Run: python3 auth_mode.py --setup-accounts or python3 auth_mode.py --setup-google-profile")
    item = data[name]
    account_b = item.get("account_b")
    return AuthProfile(
        name=item["name"],
        target_url=item["target_url"],
        login_url=item["login_url"],
        account_a=AuthAccount(**item["account_a"]),
        account_b=AuthAccount(**account_b) if account_b else None,
        notes=item.get("notes", ""),
    )


def list_profiles() -> list[str]:
    return sorted(load_all_profiles(raw=True).keys())


def redacted_profile_summary(name: str = "default") -> dict[str, Any]:
    profile = load_profile(name)
    return {
        "name": profile.name,
        "target_url": profile.target_url,
        "login_url": profile.login_url,
        "account_a": {"label": profile.account_a.label, "username": profile.account_a.username, "password": "<LOCAL_ONLY>" if profile.account_a.password else "<NOT_STORED>"},
        "account_b": {"label": profile.account_b.label, "username": profile.account_b.username, "password": "<LOCAL_ONLY>" if profile.account_b.password else "<NOT_STORED>"} if profile.account_b else None,
    }
