from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from arsenal.catalog import load_tools, tools_for_profile
from arsenal.healthcheck import run_healthcheck
from arsenal.installer import ensure_profile_tools, upgrade_tool

OUT_DIR = Path("reports/output/maintenance")
STATE_FILE = OUT_DIR / "daily-update-state.json"
INTEL_FILE = OUT_DIR / "latest-intel.json"
LOG_FILE = OUT_DIR / "daily-update.log"
SECONDS_PER_DAY = 24 * 60 * 60

INTEL_SOURCES = {
    "cisa_known_exploited": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nuclei_latest_release": "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
    "nuclei_templates_latest_release": "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest",
    "httpx_latest_release": "https://api.github.com/repos/projectdiscovery/httpx/releases/latest",
    "katana_latest_release": "https://api.github.com/repos/projectdiscovery/katana/releases/latest",
}


def _log(message: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8", errors="ignore") as handle:
        handle.write(message.rstrip() + "\n")


def _run(command: list[str]) -> dict[str, Any]:
    _log("$ " + " ".join(command))
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        _log(completed.stdout[-4000:])
        return {"command": command, "ok": completed.returncode == 0, "exit_code": completed.returncode, "output_tail": completed.stdout[-2000:]}
    except Exception as exc:
        _log(f"ERROR: {exc}")
        return {"command": command, "ok": False, "error": str(exc)}


def _fetch_json(name: str, url: str, timeout: int = 15) -> dict[str, Any]:
    try:
        req = Request(url, headers={"User-Agent": "VulnScope-DailyUpdate/1.0", "Accept": "application/json"})
        with urlopen(req, timeout=timeout) as response:
            body = response.read(1_000_000).decode("utf-8", errors="replace")
        parsed = json.loads(body)
        return {"name": name, "url": url, "ok": True, "data": _summarize_feed(name, parsed)}
    except Exception as exc:
        return {"name": name, "url": url, "ok": False, "error": str(exc)}


def _summarize_feed(name: str, data: Any) -> Any:
    if name == "cisa_known_exploited" and isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])[:30]
        return [{"cveID": v.get("cveID"), "vendorProject": v.get("vendorProject"), "product": v.get("product"), "vulnerabilityName": v.get("vulnerabilityName"), "dateAdded": v.get("dateAdded")} for v in vulns]
    if isinstance(data, dict):
        return {"tag_name": data.get("tag_name"), "name": data.get("name"), "published_at": data.get("published_at"), "html_url": data.get("html_url")}
    return data


def collect_latest_intel() -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"generated_at": time.time(), "sources": [_fetch_json(name, url) for name, url in INTEL_SOURCES.items()]}
    INTEL_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def update_nuclei_templates() -> dict[str, Any]:
    checks = []
    checks.append(_run(["bash", "-lc", "command -v nuclei >/dev/null 2>&1 && nuclei -update || true"]))
    checks.append(_run(["bash", "-lc", "command -v nuclei >/dev/null 2>&1 && nuclei -update-templates || true"]))
    return {"nuclei_updates": checks}


def run_daily_update(profile: str | None = None, install_missing: bool = True, upgrade_existing: bool = True, yes: bool = True) -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    started = time.time()
    tools = tools_for_profile(profile) if profile else load_tools()
    before = run_healthcheck(profile)
    install_state = ensure_profile_tools(tools, auto_install=install_missing, yes=yes, allow_system=True)
    upgraded = {}
    if upgrade_existing:
        for tool in tools:
            upgraded[tool.name] = upgrade_tool(tool, yes=yes, allow_system=True)
    local_updates = update_nuclei_templates()
    intel = collect_latest_intel()
    after = run_healthcheck(profile)
    result = {
        "started_at": started,
        "ended_at": time.time(),
        "profile": profile or "all",
        "before": {"installed": before.get("installed_count"), "missing": before.get("missing_count")},
        "install_state": install_state,
        "upgraded": upgraded,
        "local_updates": local_updates,
        "latest_intel_file": str(INTEL_FILE),
        "intel_sources_ok": sum(1 for item in intel.get("sources", []) if item.get("ok")),
        "after": {"installed": after.get("installed_count"), "missing": after.get("missing_count")},
        "log": str(LOG_FILE),
    }
    STATE_FILE.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def update_if_due(profile: str | None = None, max_age_seconds: int = SECONDS_PER_DAY, yes: bool = True) -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        try:
            previous = json.loads(STATE_FILE.read_text(encoding="utf-8", errors="ignore"))
            if time.time() - float(previous.get("ended_at", 0)) < max_age_seconds:
                return {"skipped": True, "reason": "daily update already completed recently", "state_file": str(STATE_FILE)}
        except Exception:
            pass
    return run_daily_update(profile=profile, yes=yes)
