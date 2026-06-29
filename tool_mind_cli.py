#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from arsenal.catalog import load_tools
from arsenal.installer import install_tool, is_installed
from mega_tools_cli import MEGA_TOOLS, as_tool
from normalizers.evidence import normalize_all

OUT = Path("reports/output/tool-mind")

BASE_TOOL_NAMES = {
    "gau", "waybackurls", "httpx", "katana", "arjun", "nuclei", "linkfinder",
    "subfinder", "assetfinder", "dnsx", "tlsx", "subjs", "uro", "unfurl", "anew", "qsreplace", "gf",
}
SIGNAL_TOOL_MAP = {
    "api_surface": {"graphw00f", "clairvoyance", "httpx", "katana", "nuclei"},
    "object_reference": {"arjun", "paramspider", "katana", "httpx"},
    "rendering_surface": {"linkfinder", "subjs", "kxss", "Gxss", "dalfox"},
    "redirect_surface": {"gau", "waybackurls", "katana", "gf", "qsreplace"},
    "file_surface": {"gobuster", "ffuf", "dirsearch", "nuclei"},
}
CATEGORY_TOOL_MAP = {
    "asset_discovery": {"subfinder", "assetfinder", "amass", "asnmap", "chaos"},
    "url_discovery": {"gau", "waybackurls", "waymore", "katana", "hakrawler", "gospider"},
    "javascript": {"linkfinder", "xnLinkFinder", "subjs", "jsbeautifier", "mantra"},
    "parameters": {"arjun", "paramspider", "uro", "unfurl", "qsreplace", "gf"},
    "api": {"graphw00f", "clairvoyance", "httpx", "katana", "nuclei"},
    "content": {"gobuster", "ffuf", "dirsearch"},
    "secrets": {"gitleaks", "trufflehog"},
    "xss_review": {"kxss", "Gxss", "dalfox", "linkfinder", "subjs"},
}


def run(cmd: list[str], timeout: int = 1200) -> dict[str, Any]:
    started = time.time()
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return {"command": cmd, "ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - started, 2), "output_tail": p.stdout[-2500:]}
    except Exception as exc:
        return {"command": cmd, "ok": False, "error": str(exc), "seconds": round(time.time() - started, 2)}


def mega_by_name() -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in MEGA_TOOLS}


def decide_tools(target: str | None = None, mode: str = "deep") -> dict[str, Any]:
    evidence = normalize_all(target)
    endpoints = evidence.get("endpoints", [])
    tags = {tag for e in endpoints for tag in e.get("risk_tags", [])}
    params = set(evidence.get("parameters", []))
    desired = set(BASE_TOOL_NAMES)
    reasoning = []

    reasoning.append({"thought": "Start with core bug-bounty evidence tools.", "tools": sorted(BASE_TOOL_NAMES)})
    if not endpoints:
        reasoning.append({"thought": "No endpoint evidence yet, so prioritize asset/URL discovery tools.", "tools": sorted(CATEGORY_TOOL_MAP["asset_discovery"] | CATEGORY_TOOL_MAP["url_discovery"])})
        desired |= CATEGORY_TOOL_MAP["asset_discovery"] | CATEGORY_TOOL_MAP["url_discovery"]
    if len(endpoints) < 30:
        reasoning.append({"thought": "Endpoint corpus is small, add crawlers and archive collectors.", "tools": sorted(CATEGORY_TOOL_MAP["url_discovery"])})
        desired |= CATEGORY_TOOL_MAP["url_discovery"]
    if params or any(tag in tags for tag in ["object_reference", "redirect_surface", "rendering_surface"]):
        reasoning.append({"thought": "Parameters or parameter-like risk tags exist, add parameter mining and normalization tools.", "tools": sorted(CATEGORY_TOOL_MAP["parameters"])})
        desired |= CATEGORY_TOOL_MAP["parameters"]
    for tag, tools in SIGNAL_TOOL_MAP.items():
        if tag in tags:
            reasoning.append({"thought": f"Observed `{tag}`, add specialist support tools.", "tools": sorted(tools)})
            desired |= tools
    if mode in {"deep", "full", "crazy"}:
        for category in ["javascript", "api", "content", "secrets", "xss_review"]:
            reasoning.append({"thought": f"Deep mode adds `{category}` support.", "tools": sorted(CATEGORY_TOOL_MAP[category])})
            desired |= CATEGORY_TOOL_MAP[category]
    return {"target": target, "mode": mode, "signals": {"endpoints": len(endpoints), "parameters": len(params), "tags": sorted(tags)}, "desired_tools": sorted(desired), "reasoning": reasoning}


def tool_status(name: str) -> dict[str, Any]:
    mega = mega_by_name()
    if name in mega:
        item = mega[name]
        tool = as_tool(item)
        supported = item.get("type") in {"go", "pipx_or_pip"}
        return {"name": name, "source": "mega", "supported": supported, "installed": is_installed(tool), "tool": tool, "meta": item}
    for tool in load_tools():
        if tool.name == name or tool.binary == name:
            return {"name": name, "source": "catalog", "supported": True, "installed": is_installed(tool), "tool": tool, "meta": {"category": tool.category, "risk": tool.risk_level}}
    return {"name": name, "source": "unknown", "supported": False, "installed": False, "tool": None, "meta": {}}


def run_tool_mind(target: str | None = None, mode: str = "deep", install_needed: bool = False, yes: bool = False) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    plan = decide_tools(target, mode)
    repair_result = None
    if install_needed:
        repair_result = run(["python3", "daily_update_cli.py", "--profile", "bug-bounty-safe", "--force", "--yes"], timeout=1800)

    rows = []
    for name in plan["desired_tools"]:
        status = tool_status(name)
        installed_before = bool(status["installed"])
        installed_after = installed_before
        install_note = "already_installed" if installed_before else "not_installed"
        if install_needed and not installed_before and status.get("supported") and status.get("tool") is not None:
            installed_after = install_tool(status["tool"], yes=yes, allow_system=True)
            install_note = "installed" if installed_after else "install_failed_or_manual_needed"
        elif not status.get("supported"):
            install_note = "tracked_manual_or_unsupported"
        rows.append({"name": name, "source": status["source"], "category": status.get("meta", {}).get("category"), "risk": status.get("meta", {}).get("risk"), "supported": status.get("supported"), "installed_before": installed_before, "installed_after": installed_after, "decision": install_note})

    payload = {**plan, "repair_result": repair_result, "tools": rows, "summary": {"desired": len(rows), "installed": len([r for r in rows if r["installed_after"]]), "missing": len([r for r in rows if not r["installed_after"]]), "manual": len([r for r in rows if r["decision"] == "tracked_manual_or_unsupported"])}}
    (OUT / "tool-mind.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Tool Mind", "", f"Target: `{target or 'not supplied'}`", f"Mode: `{mode}`", f"Desired tools: `{payload['summary']['desired']}`", f"Installed: `{payload['summary']['installed']}`", f"Missing: `{payload['summary']['missing']}`", "", "## Reasoning"]
    for item in plan["reasoning"]:
        lines.append(f"- {item['thought']} tools=`{', '.join(item['tools'])}`")
    lines += ["", "## Tool Decisions"]
    for row in rows:
        lines.append(f"- `{row['name']}` installed=`{row['installed_after']}` decision=`{row['decision']}` source=`{row['source']}`")
    (OUT / "tool-mind.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope autonomous tool mind: decide, install, and repair needed tools")
    parser.add_argument("--target")
    parser.add_argument("--mode", default="deep", choices=["base", "deep", "full", "crazy"])
    parser.add_argument("--install-needed", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    result = run_tool_mind(args.target, args.mode, install_needed=args.install_needed, yes=args.yes)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/tool-mind/tool-mind.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
