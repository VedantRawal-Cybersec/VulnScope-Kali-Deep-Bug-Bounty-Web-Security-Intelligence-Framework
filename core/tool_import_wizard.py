#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from core.tool_manager import ToolManager

PROMPT_TOKEN = "__prompt__"


def _print_tool_summary(tool: Any) -> None:
    print("\nDetected tool:")
    print(f"  ID      : {tool.tool_id}")
    print(f"  Name    : {tool.name}")
    print(f"  Version : {tool.version}")
    print(f"  Phase   : {tool.phase}")
    print(f"  Path    : {tool.local_path}")
    print(f"  Parser  : {tool.output_parser}")
    print("  Install :")
    if tool.install:
        for command in tool.install:
            print("    - " + " ".join(command))
    else:
        print("    - none detected")
    print("  Run     : " + (" ".join(tool.run) if tool.run else "not detected"))


def run_import_wizard(repo_url: str | None = None, *, yes: bool = False) -> int:
    """One-screen GitHub tool import wizard.

    User-facing flow:
      1. enter GitHub URL,
      2. VulnScope clones and detects the manifest/profile,
      3. user confirms once with INTEGRATE,
      4. VulnScope enables the tool and runs approved install steps when present.
    """
    manager = ToolManager()
    url = "" if repo_url in {None, "", PROMPT_TOKEN} else str(repo_url).strip()
    if not url:
        url = input('Enter tool GitHub URL: "').strip().strip('"').strip("'")
    if not url:
        print("No GitHub URL provided.")
        return 2

    print("\nDownloading and detecting tool profile...")
    tool = manager.add_tool(url)

    if not tool.run:
        _print_tool_summary(tool)
        run_command = input("\nRun command not detected. Enter command template using {target}, or press Enter to register only: ").strip()
        if run_command:
            tool = manager.add_tool(url, run_command=run_command)

    _print_tool_summary(tool)

    if yes:
        decision = "INTEGRATE"
    else:
        print("\nTo fully integrate this tool, VulnScope will:")
        print("  - approve the detected install profile")
        print("  - approve the detected run profile")
        print("  - enable it in tools/registry.json")
        print("  - run install steps if the manifest declared any")
        decision = input("\nType INTEGRATE to continue, or press Enter to leave it registered but disabled: ").strip()

    if decision != "INTEGRATE":
        print("\nRegistered only. Tool is not enabled yet.")
        print("Use: python3 vulnscope.py --list-tools")
        return 0

    tool = manager.registry.approve(tool.tool_id, install=True, run=True, enable=True)
    install_results = []
    if tool.install:
        print("\nInstalling detected dependencies...")
        install_results = [item.to_dict() for item in manager.install_tool(tool.tool_id, confirm=True)]
        tool = manager.registry.get(tool.tool_id) or tool

    payload = {
        "status": "integrated",
        "tool": tool.to_dict(),
        "install_results": install_results,
        "registry": "tools/registry.json",
        "next_scan_example": "python3 vulnscope.py --target https://example.com --yes --lab-mode",
    }
    print("\nTool integrated successfully.")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0
