#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from arsenal.catalog import load_tools
from arsenal.installer import is_installed
from mega_tools_cli import MEGA_TOOLS, as_tool
from normalizers.evidence import normalize_all
from tool_path_repair_cli import repair as repair_tool_paths

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


def mega_by_name() -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in MEGA_TOOLS}


def decide_tools(target: str | None = None, mode: str = "deep") -> dict[str, Any]:
    evidence = normalize_all(target)
    endpoints = evidence.get("endpoints", [])
    tags = {tag for e in endpoints for tag in e.get("risk_tags", [])}
    params = set(evidence.get("parameters", []))
    desired = set(BASE_TOOL_NAMES)
    reasoning = []
    reasoning.append({"thought": "Start with core safe evidence support tools.", "tools": sorted(BASE_TOOL_NAMES)})
    if not endpoints:
        reasoning.append({"thought": "No endpoint evidence yet, so prioritize asset and URL discovery support tools.", "tools": sorted(CATEGORY_TOOL_MAP["asset_discovery"] | CATEGORY_TOOL_MAP["url_discovery"])})
        desired |= CATEGORY_TOOL_MAP["asset_discovery"] | CATEGORY_TOOL_MAP["url_discovery"]
    if len(endpoints) < 30:
        reasoning.append({"thought": "Endpoint corpus is small, add crawler/archive support tools as optional helpers.", "tools": sorted(CATEGORY_TOOL_MAP["url_discovery"])})
        desired |= CATEGORY_TOOL_MAP["url_discovery"]
    if params or any(tag in tags for tag in ["object_reference", "redirect_surface", "rendering_surface"]):
        reasoning.append({"thought": "Parameters or parameter-like risk tags exist, add parameter-mining support tools.", "tools": sorted(CATEGORY_TOOL_MAP["parameters"])})
        desired |= CATEGORY_TOOL_MAP["parameters"]
    for tag, tools in SIGNAL_TOOL_MAP.items():
        if tag in tags:
            reasoning.append({"thought": f"Observed `{tag}`, add specialist support tools as optional helpers.", "tools": sorted(tools)})
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
    started = time.time()
    plan = decide_tools(target, mode)
    repair_result = None
    if install_needed:
        repair_result = {
            "skipped": True,
            "reason": "autonomous_no_blocking_install_mode",
            "detail": "Tool Mind now inventories desired tools and repairs PATH only. It does not install external tools during a live target scan.",
        }

    rows = []
    for name in plan["desired_tools"]:
        status = tool_status(name)
        installed = bool(status["installed"])
        if installed:
            decision = "already_installed"
        elif not status.get("supported"):
            decision = "tracked_manual_or_unsupported"
        else:
            decision = "optional_missing_not_installed_during_live_scan"
        rows.append({"name": name, "source": status["source"], "category": status.get("meta", {}).get("category"), "risk": status.get("meta", {}).get("risk"), "supported": status.get("supported"), "installed_before": installed, "installed_after": installed, "decision": decision})

    path_repair_result = repair_tool_paths(plan["desired_tools"])
    fixed = {item["binary"]: item["ok"] for item in path_repair_result.get("tools", [])}
    for row in rows:
        if fixed.get(row["name"]):
            row["installed_after"] = True
            if row["decision"].startswith("optional_missing"):
                row["decision"] = "found_after_path_repair"

    payload = {**plan, "repair_result": repair_result, "path_repair_result": path_repair_result, "tools": rows, "summary": {"desired": len(rows), "installed": len([r for r in rows if r["installed_after"]]), "missing": len([r for r in rows if not r["installed_after"]]), "manual": len([r for r in rows if r["decision"] == "tracked_manual_or_unsupported"]), "seconds": round(time.time() - started, 2)}}
    (OUT / "tool-mind.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Tool Mind", "", f"Target: `{target or 'not supplied'}`", f"Mode: `{mode}`", "Live install mode: `disabled to prevent scan blocking`", f"Desired tools: `{payload['summary']['desired']}`", f"Installed: `{payload['summary']['installed']}`", f"Missing optional: `{payload['summary']['missing']}`", "", "## Reasoning"]
    for item in plan["reasoning"]:
        lines.append(f"- {item['thought']} tools=`{', '.join(item['tools'])}`")
    lines += ["", "## Tool Decisions"]
    for row in rows:
        lines.append(f"- `{row['name']}` installed=`{row['installed_after']}` decision=`{row['decision']}` source=`{row['source']}`")
    lines += ["", "## Path Repair", f"- Repaired/found: `{path_repair_result['summary']['repaired_or_found']}`", f"- Missing: `{path_repair_result['summary']['missing']}`", "- PATH report: `reports/output/tool-path-repair/tool-path-repair.md`"]
    (OUT / "tool-mind.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope autonomous tool mind: decide and inventory support tools without blocking live scans")
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
