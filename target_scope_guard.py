#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPORT_ROOT = Path("reports/output")
CURRENT_TARGET_FILE = REPORT_ROOT / "current-target-session.json"
URL_RE = re.compile(r"https?://[^\s'\"<>),]+", re.I)


def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        raise ValueError("Target cannot be empty")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or ""
    host = host.split(":")[0].lower().strip()
    if not host:
        raise ValueError(f"Invalid target: {target}")
    return host


def session_target(default: str | None = None) -> str | None:
    if default:
        return normalize_target(default)
    if CURRENT_TARGET_FILE.exists():
        try:
            data = json.loads(CURRENT_TARGET_FILE.read_text(encoding="utf-8", errors="ignore"))
            target = data.get("target")
            if target:
                return normalize_target(str(target))
        except Exception:
            pass
    return None


def extract_urls(value: Any) -> set[str]:
    urls: set[str] = set()
    if isinstance(value, str):
        for match in URL_RE.findall(value):
            urls.add(match.rstrip("),.;]"))
    elif isinstance(value, dict):
        for item in value.values():
            urls.update(extract_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.update(extract_urls(item))
    return urls


def url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").split(":")[0].lower().strip()
    except Exception:
        return ""


def url_in_target_scope(url: str, target: str | None, include_subdomains: bool = False) -> bool:
    if not target:
        return True
    try:
        target_host = host_from_target(target)
    except Exception:
        return False
    host = url_host(url)
    if not host:
        return False
    if host == target_host:
        return True
    return bool(include_subdomains and host.endswith("." + target_host))


def object_in_target_scope(value: Any, target: str | None, include_subdomains: bool = False) -> bool:
    if not target:
        return True
    target_host = host_from_target(target)
    urls = extract_urls(value)
    if urls:
        return any(url_in_target_scope(url, target, include_subdomains=include_subdomains) for url in urls)
    text = json.dumps(value, ensure_ascii=False, default=str).lower()
    return target_host in text


def reset_target_report_state(session: dict[str, Any], preserve: set[str] | None = None) -> dict[str, Any]:
    """Remove stale target-dependent reports so a new scan cannot reuse old domains."""
    preserve = preserve or {"kai-interface"}
    target = normalize_target(str(session.get("target") or ""))
    host = host_from_target(target)
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    removed: list[str] = []

    for child in list(REPORT_ROOT.iterdir()):
        if child.name in preserve:
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
            removed.append(str(child))
        except Exception:
            pass

    CURRENT_TARGET_FILE.write_text(
        json.dumps(
            {
                "target": target,
                "host": host,
                "include_subdomains": bool(session.get("include_subdomains")),
                "confirmed_authorization": bool(session.get("confirmed_authorization")),
                "started_at": time.time(),
                "removed_previous_outputs": removed,
                "scope_lock": "Only the user-entered target host is valid for this run.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"target": target, "host": host, "removed_previous_outputs": removed}
