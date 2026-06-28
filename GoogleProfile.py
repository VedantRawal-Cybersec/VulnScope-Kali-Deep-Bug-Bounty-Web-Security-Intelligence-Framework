#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
except Exception:
    tk = None

from auth.playwright_login import playwright_available

ROOT = Path.home() / ".vulnscope" / "google_profiles"
STATE_DIR = Path("reports/output/auth/states")
GOOGLE_LOGIN = "https://accounts.google.com/"
DEFAULT_OPEN_URL = "https://myaccount.google.com/"


def _safe_name(value: str) -> str:
    return "".join(c for c in value.strip().lower().replace("@", "_at_") if c.isalnum() or c in {"_", "-", "."}) or "google_account"


def _profile_dir(label: str) -> Path:
    return ROOT / _safe_name(label)


def _state_path(label: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"google-{_safe_name(label)}-persistent.json"


def _metadata_path() -> Path:
    ROOT.mkdir(parents=True, exist_ok=True)
    return ROOT / "profiles.json"


def _load_metadata() -> dict:
    p = _metadata_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_metadata(label: str, state_path: Path, user_dir: Path, browser: str) -> None:
    data = _load_metadata()
    data[label] = {
        "label": label,
        "state_path": str(state_path),
        "browser_profile_dir": str(user_dir),
        "browser": browser,
        "note": "Password is not stored by VulnScope. This is a local Chrome/Chromium browser profile/session.",
    }
    p = _metadata_path()
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def _chrome_available() -> bool:
    return bool(shutil.which("google-chrome") or shutil.which("google-chrome-stable") or shutil.which("chromium") or shutil.which("chromium-browser"))


def _launch_context(playwright, user_dir: Path, headless: bool = False):
    """Prefer real installed Google Chrome to avoid Google blocking bundled automation Chromium."""
    launch_args = {
        "user_data_dir": str(user_dir),
        "headless": headless,
        "viewport": {"width": 1400, "height": 900},
    }
    try:
        return playwright.chromium.launch_persistent_context(channel="chrome", **launch_args), "chrome"
    except Exception:
        try:
            return playwright.chromium.launch_persistent_context(channel="chromium", **launch_args), "chromium"
        except Exception:
            return playwright.chromium.launch_persistent_context(**launch_args), "playwright-chromium"


def save_google_profile(label: str, headless: bool = False) -> Path:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")
    from playwright.sync_api import sync_playwright

    user_dir = _profile_dir(label)
    user_dir.mkdir(parents=True, exist_ok=True)
    state_path = _state_path(label)

    with sync_playwright() as p:
        context, browser_name = _launch_context(p, user_dir, headless=headless)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(GOOGLE_LOGIN, wait_until="domcontentloaded", timeout=60000)
        print("\nGoogle login window opened.")
        print(f"Browser engine: {browser_name}")
        print("Enter your Google email/password only inside the real browser window.")
        print("After login is complete, press Enter here.")
        print("If Google still says browser is not secure, install Google Chrome stable and run this again.")
        input("Press Enter after Google login is completed...")
        context.storage_state(path=str(state_path))
        context.close()

    _save_metadata(label, state_path, user_dir, browser_name)
    return state_path


def open_google_profile(label: str, url: str = DEFAULT_OPEN_URL, headless: bool = False) -> None:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")
    from playwright.sync_api import sync_playwright

    user_dir = _profile_dir(label)
    if not user_dir.exists():
        raise FileNotFoundError(f"Profile not found for {label}. Run save first.")
    with sync_playwright() as p:
        context, browser_name = _launch_context(p, user_dir, headless=headless)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        print(f"Opened saved Google profile: {label}")
        print(f"Browser engine: {browser_name}")
        print(f"Current URL: {page.url}")
        input("Press Enter to close browser...")
        context.storage_state(path=str(_state_path(label)))
        context.close()


def list_profiles() -> None:
    data = _load_metadata()
    if not data:
        print("No saved Google profiles found.")
        return
    print(json.dumps(data, indent=2))


def doctor() -> None:
    print("GoogleProfile Doctor")
    print(f"Playwright available : {playwright_available()}")
    print(f"Installed Chrome     : {_chrome_available()}")
    print(f"google-chrome        : {shutil.which('google-chrome')}")
    print(f"google-chrome-stable : {shutil.which('google-chrome-stable')}")
    print(f"chromium             : {shutil.which('chromium')}")
    print(f"chromium-browser     : {shutil.which('chromium-browser')}")
    if not _chrome_available():
        print("\nRecommended fix on Kali:")
        print("wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb")
        print("sudo apt install ./google-chrome-stable_current_amd64.deb")


def gui() -> int:
    if tk is None:
        print("Tkinter not available. Use CLI mode instead.")
        return 1
    root = tk.Tk()
    root.title("VulnScope Google Profiles")
    root.geometry("440x280")
    root.resizable(False, False)

    title = tk.Label(root, text="VulnScope Google Profile Saver", font=("Arial", 16, "bold"))
    title.pack(pady=12)
    info = tk.Label(root, text="Login happens inside Google's real login page.\nVulnScope saves browser session/profile, not your password.\nInstall Google Chrome stable if Google blocks Chromium.", justify="center")
    info.pack(pady=6)

    def save_flow():
        label = simpledialog.askstring("Profile Label", "Enter label/email for this Google account:", parent=root)
        if not label:
            return
        messagebox.showinfo("Next Step", "A Google login browser will open. Login there, then return to terminal and press Enter.")
        try:
            state = save_google_profile(label)
            messagebox.showinfo("Saved", f"Saved profile:\n{label}\n\nState:\n{state}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def open_flow():
        label = simpledialog.askstring("Profile Label", "Enter saved label/email:", parent=root)
        if not label:
            return
        try:
            open_google_profile(label)
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    tk.Button(root, text="Save / Login Google Account", command=save_flow, width=34, height=2).pack(pady=8)
    tk.Button(root, text="Open Saved Google Account", command=open_flow, width=34, height=2).pack(pady=8)
    tk.Button(root, text="Close", command=root.destroy, width=34).pack(pady=8)
    root.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple Google profile saver for VulnScope")
    parser.add_argument("--save", help="Save/login Google profile using this label/email")
    parser.add_argument("--open", help="Open saved Google profile using this label/email")
    parser.add_argument("--url", default=DEFAULT_OPEN_URL, help="URL to open with saved profile")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--doctor", action="store_true", help="Check Chrome/Playwright readiness")
    parser.add_argument("--gui", action="store_true", help="Open simple GUI launcher")
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    if args.doctor:
        doctor()
        return 0
    if args.list:
        list_profiles()
        return 0
    if args.save:
        state = save_google_profile(args.save, headless=args.headless)
        print(f"Saved Google profile: {args.save}")
        print(f"State file: {state}")
        return 0
    if args.open:
        open_google_profile(args.open, url=args.url, headless=args.headless)
        return 0
    return gui()


if __name__ == "__main__":
    raise SystemExit(main())
