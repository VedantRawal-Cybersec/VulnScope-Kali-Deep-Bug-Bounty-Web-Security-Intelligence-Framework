#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from core.tool_registry import ToolRegistry


def quiet_incomplete_tools() -> dict[str, Any]:
    """Disable enabled registry entries that cannot execute yet.

    They stay in tools/registry.json for repair/listing, but the live dashboard and
    scheduler stop treating them as runnable work.
    """
    registry = ToolRegistry()
    disabled = 0
    ready = 0
    total = 0
    changed = False
    for tool in registry.list(enabled_only=False):
        total += 1
        can_run = bool(tool.enabled and tool.approved_for_run and tool.run)
        if can_run:
            ready += 1
            continue
        if tool.enabled:
            tool.enabled = False
            tool.metadata["quieted_reason"] = "not runnable yet"
            disabled += 1
            changed = True
    if changed:
        registry.save()
    return {"total": total, "ready": ready, "disabled": disabled}
