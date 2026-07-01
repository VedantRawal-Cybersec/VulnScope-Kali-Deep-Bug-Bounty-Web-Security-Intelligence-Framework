#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        raise ValueError("target is required")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = (parsed.hostname or parsed.netloc or target).split(":")[0].lower().strip(".")
    if not host or "/" in host:
        raise ValueError(f"invalid target host: {target}")
    return host


def slug_from_target(target: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", host_from_target(target)).strip("-.") or "target"


def same_or_child_host(child: str, parent: str) -> bool:
    child = str(child or "").lower().strip(".")
    parent = str(parent or "").lower().strip(".")
    return child == parent or child.endswith("." + parent)


def is_allowed_host(candidate: str, allowed_host: str, *, include_subdomains: bool = False) -> bool:
    try:
        host = host_from_target(candidate) if "://" in str(candidate) else str(candidate).split("/")[0].split(":")[0].lower().strip(".")
    except Exception:
        return False
    return same_or_child_host(host, allowed_host) if include_subdomains else host == allowed_host


def scope_policy(target: str, *, include_subdomains: bool = False) -> dict[str, Any]:
    host = host_from_target(target)
    return {
        "target": normalize_target(target),
        "root_host": host,
        "include_subdomains": bool(include_subdomains),
        "allowed_match": "root_and_subdomains" if include_subdomains else "root_host_only",
        "zero_impact_mode": True,
        "safe_methods_only": True,
        "default_rate_limit_per_second": 5,
    }


def cai_output_dir(target: str) -> Path:
    return Path("reports/output/cai-superior") / slug_from_target(target)
