#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuthProfile:
    name: str
    role: str = "user"
    headers: dict[str, str] = field(default_factory=dict)
    cookie: str = ""
    bearer_token: str = ""
    basic_auth: str = ""
    storage_state: str = ""
    notes: str = ""

    def masked(self) -> dict[str, Any]:
        safe_headers = {}
        for k, v in self.headers.items():
            low = k.lower()
            safe_headers[k] = "<redacted>" if low in {"authorization", "cookie", "x-api-key", "x-auth-token"} else str(v)[:120]
        return {"name": self.name, "role": self.role, "headers": safe_headers, "cookie": "<set>" if self.cookie else "", "bearer_token": "<set>" if self.bearer_token else "", "basic_auth": "<set>" if self.basic_auth else "", "storage_state": self.storage_state, "notes": self.notes}

    def request_headers(self) -> dict[str, str]:
        out = dict(self.headers)
        if self.cookie:
            out["Cookie"] = self.cookie
        if self.bearer_token:
            out["Authorization"] = "Bearer " + self.bearer_token
        if self.basic_auth:
            out["Authorization"] = "Basic " + self.basic_auth
        return out


def _load_cookie_file(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8", errors="ignore").strip()
    if "\t" in text:
        cookies = []
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies.append(f"{parts[5]}={parts[6]}")
        return "; ".join(cookies)
    return text


def load_auth_profiles(path: str | Path | None = None) -> list[AuthProfile]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"auth profile file not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    rows = raw.get("profiles", raw) if isinstance(raw, dict) else raw
    profiles: list[AuthProfile] = []
    for index, row in enumerate(rows or []):
        if not isinstance(row, dict):
            continue
        cookie = str(row.get("cookie") or "")
        if row.get("cookie_file"):
            cookie = _load_cookie_file(str(row.get("cookie_file"))) or cookie
        headers = {str(k): str(v) for k, v in dict(row.get("headers") or {}).items()}
        profiles.append(AuthProfile(name=str(row.get("name") or f"profile_{index+1}"), role=str(row.get("role") or row.get("name") or "user"), headers=headers, cookie=cookie, bearer_token=str(row.get("bearer_token") or ""), basic_auth=str(row.get("basic_auth") or ""), storage_state=str(row.get("storage_state") or ""), notes=str(row.get("notes") or "")))
    return profiles


def headers_from_cli(*, cookie: str = "", cookie_file: str = "", bearer_token: str = "", basic_auth: str = "") -> list[str]:
    headers: list[str] = []
    cookie_value = cookie or _load_cookie_file(cookie_file)
    if cookie_value:
        headers.append("Cookie: " + cookie_value)
    if bearer_token:
        headers.append("Authorization: Bearer " + bearer_token)
    if basic_auth:
        headers.append("Authorization: Basic " + basic_auth)
    return headers


def write_auth_template(path: str | Path = "auth-profiles.example.json") -> str:
    p = Path(path)
    payload = {"profiles": [{"name": "anonymous", "role": "anonymous", "headers": {}}, {"name": "normal_user", "role": "user", "cookie_file": "cookies-user.txt", "headers": {}}, {"name": "admin_user", "role": "admin", "cookie_file": "cookies-admin.txt", "headers": {}}]}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(p)
