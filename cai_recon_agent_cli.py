#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cai_asset_graph import build_asset_graph, write_asset_graph
from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, is_allowed_host, normalize_target
from cai_target_profiler_cli import build_target_profile, write_profile_reports

MAX_ITEMS = 500


def run_command(command: list[str], *, timeout: int = 90, input_text: str | None = None) -> dict[str, Any]:
    started = time.time()
    tool = command[0]
    if not shutil.which(tool):
        return {"status": "missing_tool", "tool": tool, "detail": f"{tool} is not installed or not in PATH", "seconds": 0.0}
    try:
        proc = subprocess.run(command, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL)
        return {"status": "ok" if proc.returncode == 0 else "nonzero_exit", "tool": tool, "exit_code": proc.returncode, "stdout": proc.stdout[-20000:], "seconds": round(time.time() - started, 2)}
    except subprocess.TimeoutExpired as exc:
        return handled_error(component="recon_agent", action="run_" + tool, error=exc, fallback_used="timeout_continue")
    except Exception as exc:
        return handled_error(component="recon_agent", action="run_" + tool, error=exc)


def unique_sorted(values: list[str]) -> list[str]:
    cleaned = [str(x).strip().strip(".").lower() for x in values if str(x).strip()]
    return sorted(dict.fromkeys(cleaned))[:MAX_ITEMS]


def output_lines(result: dict[str, Any]) -> list[str]:
    if not isinstance(result, dict) or not result.get("stdout"):
        return []
    return [x.strip() for x in str(result.get("stdout") or "").splitlines() if x.strip()]


def collect_tool_subdomains(host: str) -> tuple[list[str], dict[str, Any]]:
    collectors = {
        "subfinder": ["subfinder", "-silent", "-d", host],
        "assetfinder": ["assetfinder", "--subs-only", host],
        "amass_passive": ["amass", "enum", "-passive", "-d", host],
    }
    all_subs: list[str] = []
    status: dict[str, Any] = {}
    for name, cmd in collectors.items():
        result = run_command(cmd, timeout=120)
        rows = [x for x in output_lines(result) if is_allowed_host(x, host, include_subdomains=True)]
        all_subs.extend(rows)
        status[name] = {"status": result.get("status"), "items": len(rows), "detail": result.get("detail") or result.get("exit_code")}
    return unique_sorted(all_subs), status


def fetch_json_url(url: str, *, timeout: int = 20) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScope-CAI-Superior/1.0 zero-impact recon"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(2_000_000).decode("utf-8", errors="ignore")
    return json.loads(raw)


def collect_crtsh(host: str) -> tuple[list[str], dict[str, Any]]:
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + host) + "&output=json"
    try:
        data = fetch_json_url(url, timeout=25)
        names: list[str] = []
        if isinstance(data, list):
            for row in data[:1000]:
                for name in str(row.get("name_value", "")).replace("*.", "").splitlines():
                    name = name.strip().lower().strip(".")
                    if is_allowed_host(name, host, include_subdomains=True):
                        names.append(name)
        names = unique_sorted(names)
        return names, {"status": "ok", "items": len(names), "source": "crt.sh"}
    except Exception as exc:
        return [], handled_error(component="recon_agent", action="crtsh", error=exc, fallback_used="certificate_transparency_unavailable")


def collect_historical_urls(host: str) -> tuple[list[str], dict[str, Any]]:
    status: dict[str, Any] = {}
    urls: list[str] = []
    gau = run_command(["gau", host], timeout=120)
    gau_urls = [x for x in output_lines(gau) if is_allowed_host(x, host, include_subdomains=True)]
    urls.extend(gau_urls)
    status["gau"] = {"status": gau.get("status"), "items": len(gau_urls), "detail": gau.get("detail") or gau.get("exit_code")}

    wayback = run_command(["waybackurls"], timeout=120, input_text=host + "\n")
    wb_urls = [x for x in output_lines(wayback) if is_allowed_host(x, host, include_subdomains=True)]
    urls.extend(wb_urls)
    status["waybackurls"] = {"status": wayback.get("status"), "items": len(wb_urls), "detail": wayback.get("detail") or wayback.get("exit_code")}
    return unique_sorted(urls), status


def collect_commoncrawl_hint(host: str) -> tuple[list[str], dict[str, Any]]:
    # Uses Common Crawl index only. Failure is expected on restricted networks and is non-blocking.
    index = os.getenv("VULNSCOPE_COMMONCRAWL_INDEX", "CC-MAIN-2025-51")
    url = f"https://index.commoncrawl.org/{index}-index?url=*.{urllib.parse.quote(host)}/*&output=json&fl=url&collapse=urlkey"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScope-CAI-Superior/1.0 zero-impact recon"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read(1_500_000).decode("utf-8", errors="ignore")
        rows: list[str] = []
        for line in raw.splitlines()[:MAX_ITEMS]:
            try:
                item = json.loads(line)
                value = str(item.get("url") or "").strip()
                if value and is_allowed_host(value, host, include_subdomains=True):
                    rows.append(value)
            except Exception:
                continue
        rows = unique_sorted(rows)
        return rows, {"status": "ok", "items": len(rows), "source": index}
    except Exception as exc:
        return [], handled_error(component="recon_agent", action="commoncrawl", error=exc, fallback_used="commoncrawl_unavailable")


def repository_hint_status(host: str) -> dict[str, Any]:
    # The agent does not print sensitive values. Token-based integrations can be added later with masking.
    enabled = bool(os.getenv("GITHUB_TOKEN") or os.getenv("GITLAB_TOKEN"))
    return {
        "status": "configured_but_passive_placeholder" if enabled else "not_configured",
        "items": 0,
        "detail": "Repository mining is limited to masked endpoint metadata and is disabled unless a token is configured.",
    }


def aggregator_status() -> dict[str, Any]:
    return {
        "shodan": {"status": "not_configured" if not os.getenv("SHODAN_API_KEY") else "configured_placeholder", "items": 0},
        "censys": {"status": "not_configured" if not (os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET")) else "configured_placeholder", "items": 0},
        "virustotal": {"status": "not_configured" if not os.getenv("VT_API_KEY") else "configured_placeholder", "items": 0},
    }


def run_recon(target: str, *, include_subdomains: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    write_log(f"running CAI Superior Layer 1 recon for {host}")
    tool_subdomains, tool_status = collect_tool_subdomains(host)
    crt_subdomains, crt_status = collect_crtsh(host)
    historical_urls, historical_status = collect_historical_urls(host)
    cc_urls, cc_status = collect_commoncrawl_hint(host)
    subdomains = unique_sorted([host, *tool_subdomains, *crt_subdomains])
    urls = unique_sorted([*historical_urls, *cc_urls])
    collector_status: dict[str, Any] = {}
    collector_status.update(tool_status)
    collector_status["crtsh"] = crt_status
    collector_status.update(historical_status)
    collector_status["commoncrawl"] = cc_status
    collector_status["repository_hints"] = repository_hint_status(host)
    collector_status.update({f"aggregator_{k}": v for k, v in aggregator_status().items()})
    return {
        "target": target,
        "host": host,
        "generated_at": time.time(),
        "layer": 1,
        "mode": "zero-impact-passive-recon",
        "include_subdomains": include_subdomains,
        "subdomains": subdomains,
        "historical_urls": urls,
        "collector_status": collector_status,
        "safety": {
            "direct_state_change": False,
            "unsafe_payloads": False,
            "http_methods_used_for_testing": [],
            "notes": "Layer 1 collects passive/open-source discovery signals and local tool outputs only.",
        },
    }


def write_recon_reports(target: str, profile: dict[str, Any], recon: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "recon-agent.json", recon)
    graph = build_asset_graph(target, profile, recon)
    write_asset_graph(out_dir, graph)
    checkpoint = {
        "checkpoint": 1,
        "name": "Reconnaissance & Asset Discovery Agent",
        "status": "completed",
        "target": target,
        "host": recon.get("host"),
        "summary": {
            "subdomains": len(recon.get("subdomains", []) or []),
            "historical_urls": len(recon.get("historical_urls", []) or []),
            "asset_graph_nodes": graph.get("summary", {}).get("nodes", 0),
            "asset_graph_edges": graph.get("summary", {}).get("edges", 0),
            "collectors": len(recon.get("collector_status", {})),
        },
        "reports": {
            "json": str(out_dir / "recon-agent.json"),
            "markdown": str(out_dir / "recon-agent.md"),
            "asset_graph_json": str(out_dir / "asset-graph.json"),
            "asset_graph_markdown": str(out_dir / "asset-graph.md"),
        },
        "generated_at": time.time(),
    }
    write_json(out_dir / "checkpoint-1.json", checkpoint)
    lines = [
        "# CAI Superior Checkpoint 1 — Reconnaissance & Asset Discovery",
        "",
        f"Target: `{target}`",
        f"Host: `{recon.get('host')}`",
        f"Mode: `{recon.get('mode')}`",
        f"Subdomains: `{len(recon.get('subdomains', []) or [])}`",
        f"Historical URLs: `{len(recon.get('historical_urls', []) or [])}`",
        f"Asset graph nodes: `{graph.get('summary', {}).get('nodes', 0)}`",
        f"Asset graph edges: `{graph.get('summary', {}).get('edges', 0)}`",
        "",
        "## Collector Status",
    ]
    for name, status in recon.get("collector_status", {}).items():
        lines.append(f"- `{name}` status=`{status.get('status')}` items=`{status.get('items', 0)}` detail=`{status.get('detail', '')}`")
    lines += ["", "## Subdomains"]
    for item in (recon.get("subdomains", []) or [])[:200]:
        lines.append(f"- `{item}`")
    lines += ["", "## Historical URLs"]
    for item in (recon.get("historical_urls", []) or [])[:200]:
        lines.append(f"- `{item}`")
    write_markdown(out_dir / "recon-agent.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior Layer 1 passive reconnaissance agent")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    args = parser.parse_args()
    profile = build_target_profile(args.target, include_subdomains=args.include_subdomains)
    write_profile_reports(profile)
    recon = run_recon(args.target, include_subdomains=args.include_subdomains)
    checkpoint = write_recon_reports(args.target, profile, recon)
    print(json.dumps(checkpoint, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
