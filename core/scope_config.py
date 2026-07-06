#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScopeConfig:
    target: str = ""
    mode: str = "safe-active"
    include_subdomains: bool = False
    allowed_domains: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    seed_urls: list[str] = field(default_factory=list)
    api_seeds: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    auth_profiles_file: str = ""
    environment: str = "authorized"
    owner: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "include_subdomains": self.include_subdomains,
            "allowed_domains": self.allowed_domains,
            "out_of_scope": self.out_of_scope,
            "seed_urls": self.seed_urls,
            "api_seeds": self.api_seeds,
            "headers": self.headers,
            "auth_profiles_file": self.auth_profiles_file,
            "environment": self.environment,
            "owner": self.owner,
            "notes": self.notes,
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        parts = [item.strip() for item in value.replace("\n", ",").split(",")]
        return [item for item in parts if item]
    return [str(value).strip()] if str(value).strip() else []


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_key = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - ") and current_key:
            data.setdefault(current_key, []).append(line[4:].strip().strip('"\''))
            continue
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            if not value:
                data[current_key] = []
            elif value.lower() in {"true", "false"}:
                data[current_key] = value.lower() == "true"
            elif value.startswith("[") and value.endswith("]"):
                try:
                    data[current_key] = json.loads(value)
                except Exception:
                    data[current_key] = _as_list(value.strip("[]"))
            else:
                data[current_key] = value.strip('"\'')
    return data


def load_scope_config(path: str | Path | None) -> ScopeConfig:
    if not path:
        return ScopeConfig()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {p}")
    text = p.read_text(encoding="utf-8", errors="ignore")
    try:
        raw = json.loads(text)
    except Exception:
        raw = _parse_simple_yaml(text)
    cfg = ScopeConfig(
        target=str(raw.get("target") or raw.get("url") or "").strip(),
        mode=str(raw.get("mode") or raw.get("scan_mode") or "safe-active").strip(),
        include_subdomains=bool(raw.get("include_subdomains", False)),
        allowed_domains=_as_list(raw.get("allowed_domains") or raw.get("domains")),
        out_of_scope=_as_list(raw.get("out_of_scope") or raw.get("denylist")),
        seed_urls=_as_list(raw.get("seed_urls") or raw.get("urls") or raw.get("seeds")),
        api_seeds=_as_list(raw.get("api_seeds") or raw.get("apis")),
        headers=_as_list(raw.get("headers")),
        auth_profiles_file=str(raw.get("auth_profiles_file") or raw.get("auth_profiles") or "").strip(),
        environment=str(raw.get("environment") or "authorized"),
        owner=str(raw.get("owner") or ""),
        notes=str(raw.get("notes") or ""),
    )
    return cfg


def write_scope_template(path: str | Path = "scope.example.yml") -> str:
    p = Path(path)
    content = """target: https://internal.example.local
mode: safe-active
include_subdomains: false
allowed_domains:
  - internal.example.local
out_of_scope:
  - payments.internal.example.local
seed_urls:
  - https://internal.example.local/dashboard
api_seeds:
  - https://internal.example.local/api/health
headers:
  - X-Assessment: VulnScope
auth_profiles_file: auth-profiles.example.json
environment: internal\-owner: Security Team
notes: Authorized internal assessment only.
""".replace("internal\-owner", "owner")
    p.write_text(content, encoding="utf-8")
    return str(p)
