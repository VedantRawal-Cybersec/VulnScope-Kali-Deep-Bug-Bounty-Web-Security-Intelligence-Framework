from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from agent.approval_gate import assess_command_safety
from arsenal.catalog import ArsenalTool
from arsenal.installer import GO_BIN, is_installed


def render_command(tool: ArsenalTool, url: str) -> list[str]:
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    binary = _resolve_binary(tool)
    rendered = tool.safe_command_template.format(url=shlex.quote(url), host=shlex.quote(host), binary=shlex.quote(binary))
    return ["bash", "-lc", rendered]


def run_tool(tool: ArsenalTool, url: str, yes: bool = False, dry_run: bool = False) -> dict:
    output_file = Path(tool.output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if not is_installed(tool):
        return {"tool": tool.name, "ok": False, "reason": "not installed", "output_file": str(output_file)}

    command = render_command(tool, url)
    safety = assess_command_safety(command)
    if not safety.approved:
        return {"tool": tool.name, "ok": False, "reason": safety.reason, "output_file": str(output_file)}

    if tool.requires_approval and not yes:
        print("\n┌──────────────────── Tool Run Approval ────────────────────┐")
        print(f"Tool    : {tool.name}")
        print(f"Risk    : {tool.risk_level}")
        print(f"Command : {' '.join(command)}")
        print("└────────────────────────────────────────────────────────────┘")
        answer = input("Run this tool on authorized in-scope target? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            return {"tool": tool.name, "ok": False, "reason": "not approved", "output_file": str(output_file)}

    if dry_run:
        print("[DRY-RUN] " + " ".join(command))
        return {"tool": tool.name, "ok": True, "reason": "dry-run", "output_file": str(output_file), "command": command}

    print(f"[+] Running {tool.name}")
    with output_file.open("w", encoding="utf-8", errors="ignore") as handle:
        code = subprocess.call(command, stdout=handle, stderr=subprocess.STDOUT)
    return {"tool": tool.name, "ok": code == 0, "exit_code": code, "output_file": str(output_file), "command": command}


def _resolve_binary(tool: ArsenalTool) -> str:
    from shutil import which

    found = which(tool.binary)
    if found:
        return found
    go_path = GO_BIN / tool.binary
    if go_path.exists():
        return str(go_path)
    return tool.binary
