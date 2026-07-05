#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any

from core.tool_manager import ToolManager
from core.tool_registry import RegisteredTool, ToolArgument, ToolRegistry

TOOLS_DIR = Path("tools")
LOG_PATH = Path("logs/tool_suite_integration.json")

SAFE_TOOL_PROFILES: dict[str, dict[str, Any]] = {
    "nuclei": {"phase": "validation", "parser": "jsonl", "run": ["nuclei", "-u", "{target}", "-jsonl", "-silent", "-severity", "info,low,medium", "-rate-limit", "5", "-no-interactsh", "-disable-update-check"]},
    "katana": {"phase": "discovery", "parser": "jsonl", "run": ["katana", "-u", "{target}", "-jsonl", "-silent", "-d", "2", "-ct", "120"]},
    "httpx": {"phase": "recon", "parser": "jsonl", "run": ["httpx", "-u", "{target}", "-json", "-silent", "-follow-redirects"]},
    "subfinder": {"phase": "recon", "parser": "jsonl", "run": ["subfinder", "-d", "{host}", "-json", "-silent"]},
    "dnsx": {"phase": "recon", "parser": "jsonl", "run": ["dnsx", "-d", "{host}", "-json", "-silent", "-rl", "50"]},
    "naabu": {"phase": "recon", "parser": "jsonl", "run": ["naabu", "-host", "{host}", "-json", "-silent", "-rate", "100"]},
    "wafw00f": {"phase": "recon", "parser": "plain", "run": ["wafw00f", "{target}", "-a"]},
    "whatweb": {"phase": "recon", "parser": "plain", "run": ["whatweb", "--no-errors", "--log-brief=-", "{target}"]},
    "waybackurls": {"phase": "discovery", "parser": "plain", "run": ["waybackurls", "{host}"]},
    "gau": {"phase": "discovery", "parser": "plain", "run": ["gau", "--subs", "{host}"]},
    "hakrawler": {"phase": "discovery", "parser": "plain", "run": ["hakrawler", "-url", "{target}", "-depth", "2", "-plain"]},
    "gospider": {"phase": "discovery", "parser": "plain", "run": ["gospider", "-s", "{target}", "-d", "2", "--quiet"]},
    "arjun": {"phase": "discovery", "parser": "json", "run": ["arjun", "-u", "{target}", "-oJ", "-"]},
    "dirsearch": {"phase": "discovery", "parser": "plain", "run": ["dirsearch", "-u", "{target}", "--plain-text-report", "-", "--threads", "5", "--timeout", "8", "--random-agent"]},
    "feroxbuster": {"phase": "discovery", "parser": "jsonl", "run": ["feroxbuster", "-u", "{target}", "--json", "--rate-limit", "50", "--depth", "2", "-k"]},
    "ffuf": {"phase": "discovery", "parser": "json", "run": ["ffuf", "-u", "{target}/FUZZ", "-w", "{wordlist}", "-of", "json", "-rate", "50", "-t", "5"]},
}

MANUAL_ONLY = {"sqlmap", "dalfox", "xsstrike", "commix", "metasploit", "msfconsole"}


def _match_profile(path_name: str) -> str:
    value = path_name.lower().replace("_", "-")
    for name in sorted(SAFE_TOOL_PROFILES, key=len, reverse=True):
        key = name.lower().replace("_", "-")
        if key == value or key in value:
            return name
    for name in MANUAL_ONLY:
        if name in value:
            return name
    return ""


def _tool_id(name: str) -> str:
    return "suite_" + name.lower().replace("-", "_").replace(".", "_")


def _make_tool(name: str, local_path: Path, profile: dict[str, Any], *, approve_safe: bool) -> RegisteredTool:
    return RegisteredTool(
        tool_id=_tool_id(name),
        name=name,
        version="local",
        repo_url="file://" + local_path.as_posix(),
        local_path=str(local_path),
        phase=str(profile["phase"]),
        install=[],
        run=[str(item) for item in profile["run"]],
        arguments=[ToolArgument(name="target", description="Target URL", required=True)],
        output_parser=str(profile["parser"]),
        approved_for_install=True,
        approved_for_run=approve_safe,
        installed=True,
        enabled=approve_safe,
        metadata={"suite_integrated": True, "known_safe_profile": name, "source": "system-or-local"},
    )


def integrate_tools(*, approve_safe: bool = True) -> dict[str, Any]:
    registry = ToolRegistry()
    manager = ToolManager(registry)
    base = manager.reconcile_installed_tools(approve_known=True, enable=True)
    integrated: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []
    seen: set[str] = set()

    for name, profile in SAFE_TOOL_PROFILES.items():
        binary = shutil.which(name)
        local_path = Path(binary).parent if binary else None
        if not local_path and TOOLS_DIR.exists():
            for item in TOOLS_DIR.iterdir():
                if item.is_dir() and _match_profile(item.name) == name:
                    local_path = item
                    break
        if not local_path:
            continue
        tool = _make_tool(name, local_path, profile, approve_safe=approve_safe)
        registry.upsert(tool)
        integrated.append({"tool_id": tool.tool_id, "name": tool.name, "phase": tool.phase, "approved_run": tool.approved_for_run, "run": tool.run, "local_path": tool.local_path})
        seen.add(name)

    if TOOLS_DIR.exists():
        for item in sorted(TOOLS_DIR.iterdir()):
            if not item.is_dir():
                continue
            matched = _match_profile(item.name)
            if matched in SAFE_TOOL_PROFILES or not matched:
                continue
            manual.append({"path": str(item), "name_hint": matched, "reason": "manual profile required before run approval"})

    rows = registry.as_table_rows()
    ready = sum(1 for row in rows if row.get("enabled") and row.get("approved_run"))
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base_reconcile": base,
        "known_profiles": sorted(SAFE_TOOL_PROFILES),
        "integrated": integrated,
        "manual_review": manual,
        "registry_total": len(rows),
        "ready": ready,
        "registry": str(registry.path),
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Integrate local known-safe tool profiles into VulnScope registry")
    parser.add_argument("--no-approve", action="store_true", help="Register profiles but do not enable run approval")
    args = parser.parse_args(argv)
    print(json.dumps(integrate_tools(approve_safe=not args.no_approve), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
