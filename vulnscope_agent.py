#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
import shlex
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

ROOT = Path(__file__).resolve().parent
OUT = Path("reports/output/neural-agent")
MEMORY_DB = OUT / "agent-memory.sqlite3"
THINKING_LOG = OUT / "thinking-log.md"
STATE_JSON = OUT / "agent-state.json"
DEFAULT_CONFIG = Path("agent_config.yaml")

ACTIONS: dict[str, str] = {
    "preflight": "python3 mission_preflight_cli.py --target {target} --scope-policy {scope_policy}",
    "repair": "python3 tool_path_repair_cli.py",
    "coverage": "python3 coverage_matrix.py",
    "recon": "python3 domain_recon_cli.py --target {host}",
    "public": "python3 aegis_public_search_cli.py --target {target}",
    "feedback": "python3 aegis_feedback_cli.py --target {target}",
    "artemis": "python3 artemis_autonomous_cli.py --config {artemis_config} --scope-policy {scope_policy} --once",
    "loop": "python3 safe_loop_v2_cli.py --target {target} --mode comprehensive --scope-policy {scope_policy} --max-cycles 4 --yes",
    "suite": "python3 comprehensive_suite_cli.py --target {target} --scope-policy {scope_policy} --yes",
    "normalize": "python3 normalize_cli.py --target {target}",
    "graph": "python3 asset_graph_cli.py --target {target}",
    "api": "python3 api_intel_cli.py --target {target}",
    "cards": "python3 evidence_cards_cli.py --target {target}",
    "rank": "python3 reportability_cli.py --target {target}",
    "verdicts": "python3 mission_verdicts_cli.py --target {target}",
    "report": "python3 report_v2_cli.py --target {target}",
    "summary": "python3 jarvis_summary_cli.py --target {target}",
}

ORDER = ["preflight", "repair", "coverage", "recon", "public", "feedback", "artemis", "loop", "suite", "normalize", "graph", "api", "cards", "rank", "verdicts", "report", "summary"]


@dataclass
class AgentConfig:
    target: str
    hosts: list[str]
    scope_policy: str = "scope_policy.session.yaml"
    model_provider: str = "none"
    model_name: str = "llama3"
    cycles: int = 12
    verbosity: str = "normal"
    dry_run: bool = False


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("target is empty")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"invalid target: {target}")
    return host.lower()


def setup_logging(verbosity: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbosity == "debug" else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s", handlers=[logging.FileHandler(OUT / "agent.log", encoding="utf-8"), logging.StreamHandler()], force=True)


def load_config(path: str | Path) -> AgentConfig:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) if yaml and p.suffix.lower() in {".yaml", ".yml"} else json.loads(p.read_text(encoding="utf-8"))
    target = normalize_target(str(data.get("target") or ""))
    hosts = list(data.get("hosts") or [host_from_target(target)])
    return AgentConfig(target=target, hosts=hosts, scope_policy=str(data.get("scope_policy", "scope_policy.session.yaml")), model_provider=str(data.get("model_provider", "none")), model_name=str(data.get("model_name", "llama3")), cycles=int(data.get("cycles", 12)), verbosity=str(data.get("verbosity", "normal")), dry_run=bool(data.get("dry_run", False)))


def host_ok(host: str, hosts: list[str]) -> bool:
    for item in hosts:
        item = item.lower().strip()
        if item.startswith("*.") and host.endswith(item[1:]):
            return True
        if host == item:
            return True
    return False


def guard_web_rules(target: str) -> dict[str, Any]:
    parsed = urlparse(target)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    sec_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
    robot = RobotFileParser()
    result = {"robots_url": robots_url, "robots_ok": True, "security_txt_url": sec_url, "security_txt_found": False}
    try:
        robot.set_url(robots_url)
        robot.read()
        result["robots_ok"] = bool(robot.can_fetch("VulnScope-Neural-Agent", target))
    except Exception as exc:
        result["robots_error"] = str(exc)
    try:
        req = Request(sec_url, headers={"User-Agent": "VulnScope-Neural-Agent/1.0"})
        with urlopen(req, timeout=10) as response:
            result["security_txt_found"] = True
            result["security_txt_preview"] = response.read(1500).decode("utf-8", errors="ignore")
    except Exception as exc:
        result["security_txt_error"] = str(exc)
    return result


def memory() -> sqlite3.Connection:
    OUT.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(MEMORY_DB)
    con.execute("create table if not exists actions(id integer primary key, ts real, target text, action text, ok integer, score real, summary text)")
    con.execute("create table if not exists reflections(id integer primary key, ts real, target text, text text)")
    con.commit()
    return con


def think(title: str, body: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    THINKING_LOG.open("a", encoding="utf-8").write(f"\n## {time.strftime('%Y-%m-%d %H:%M:%S')} - {title}\n\n{body}\n")
    print(f"\n[THINK] {title}\n{body}")


def read_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def observed_state() -> dict[str, Any]:
    files = {"preflight": "reports/output/mission-preflight/preflight.json", "verdicts": "reports/output/mission-verdicts/mission-verdicts.json", "rank": "reports/output/reportability/reportability.json", "artemis": "reports/output/artemis/run/artemis-run.json"}
    state: dict[str, Any] = {}
    for name, path in files.items():
        data = read_json(path)
        if isinstance(data, dict):
            state[name] = data.get("summary") or {k: data.get(k) for k in ["ok", "reason", "target"] if k in data}
    return state


def choose_next(done: set[str]) -> str | None:
    for action in ORDER:
        if action not in done:
            return action
    return None


def model_hint(config: AgentConfig, state: dict[str, Any], done: list[str]) -> str | None:
    if config.model_provider != "ollama":
        return None
    prompt = json.dumps({"allowed_actions": ORDER, "target": config.target, "state": state, "done": done})
    try:
        req = Request("http://127.0.0.1:11434/api/generate", data=json.dumps({"model": config.model_name, "prompt": prompt, "stream": False}).encode(), headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=30) as response:
            text = json.loads(response.read().decode("utf-8", errors="ignore")).get("response", "")
        for action in ORDER:
            if re.search(rf"\b{re.escape(action)}\b", text):
                return action
    except Exception as exc:
        logging.warning("model_hint_failed %s", exc)
    return None


def artemis_config(target: str) -> Path:
    p = OUT / "agent-artemis.yaml"
    p.write_text("\n".join(["targets:", f"  - {target}", "passive_only: true", "require_scope_policy: true", "interval_minutes: 360", "report_every_cycles: 1", "google_search_limit: 5", "max_public_records: 500", "respect_rate_limits: true", "no_secret_values_in_reports: true", ""]), encoding="utf-8")
    return p


def command_for(action: str, config: AgentConfig, artemis: Path) -> list[str]:
    host = host_from_target(config.target)
    command = ACTIONS[action].format(target=shlex.quote(config.target), host=shlex.quote(host), scope_policy=shlex.quote(config.scope_policy), artemis_config=shlex.quote(str(artemis)))
    return ["bash", "-lc", command]


def act(action: str, config: AgentConfig, artemis: Path) -> dict[str, Any]:
    command = command_for(action, config, artemis)
    think("Act", f"Running `{action}` with command `{command[-1]}`")
    if config.dry_run:
        return {"action": action, "ok": True, "dry_run": True, "seconds": 0, "output_tail": "dry-run"}
    started = time.time()
    try:
        proc = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600)
        return {"action": action, "ok": proc.returncode == 0, "exit_code": proc.returncode, "seconds": round(time.time() - started, 2), "output_tail": proc.stdout[-4000:]}
    except Exception as exc:
        return {"action": action, "ok": False, "error": str(exc), "seconds": round(time.time() - started, 2), "output_tail": ""}


def reflect(action: str, result: dict[str, Any], state: dict[str, Any]) -> tuple[float, str]:
    score = 1.0 if result.get("ok") else -0.25
    text = f"`{action}` ended with ok={result.get('ok')} in {result.get('seconds')}s."
    if state.get("verdicts"):
        text += f" Current verdict summary: {state.get('verdicts')}"
    return score, text


def save_state(config: AgentConfig, cycle: int, done: list[str], last: dict[str, Any] | None, state: dict[str, Any]) -> None:
    STATE_JSON.write_text(json.dumps({"target": config.target, "cycle": cycle, "done": done, "last": last, "state": state, "thinking_log": str(THINKING_LOG), "memory": str(MEMORY_DB)}, indent=2, ensure_ascii=False), encoding="utf-8")


def run(config: AgentConfig) -> int:
    setup_logging(config.verbosity)
    print("FOR AUTHORIZED REVIEW ONLY - DO NOT RUN ON SYSTEMS WITHOUT PERMISSION.")
    host = host_from_target(config.target)
    if not host_ok(host, config.hosts):
        raise SystemExit(f"Host {host} is not listed in agent_config.yaml")
    rules = guard_web_rules(config.target)
    think("Perceive", f"Target `{config.target}` host `{host}`. Web rules: {rules}")
    if rules.get("robots_ok") is False:
        raise SystemExit("robots.txt disallows this path for the agent user-agent")
    con = memory()
    art = artemis_config(config.target)
    done: set[str] = set()
    last: dict[str, Any] | None = None
    for cycle in range(1, max(1, config.cycles) + 1):
        state = observed_state()
        think("Observe", f"Cycle {cycle}. Observed state keys: {list(state.keys())}. Done: {sorted(done)}")
        hinted = model_hint(config, state, sorted(done))
        action = hinted if hinted and hinted not in done else choose_next(done)
        if not action:
            think("Plan", "No remaining action. Moving to final report actions.")
            break
        think("Plan", f"Selected `{action}` using {'model hint' if hinted == action else 'rule sequence'}.")
        result = act(action, config, art)
        done.add(action)
        new_state = observed_state()
        score, note = reflect(action, result, new_state)
        think("Reflect", note)
        con.execute("insert into actions(ts,target,action,ok,score,summary) values(?,?,?,?,?,?)", (time.time(), config.target, action, 1 if result.get("ok") else 0, score, result.get("output_tail", "")[-1200:]))
        con.execute("insert into reflections(ts,target,text) values(?,?,?)", (time.time(), config.target, note))
        con.commit()
        last = result
        save_state(config, cycle, sorted(done), last, new_state)
    think("Learn", f"Saved {len(done)} actions into `{MEMORY_DB}`. Generating final outputs.")
    for final_action in ["verdicts", "report", "summary"]:
        if final_action not in done:
            act(final_action, config, art)
    save_state(config, config.cycles, sorted(done), last, observed_state())
    print(f"Thinking log: {THINKING_LOG}")
    print(f"Memory DB: {MEMORY_DB}")
    print("Final report: reports/output/report-v2/executive-report-v2.md")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope neural review agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--target")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.target:
        cfg.target = normalize_target(args.target)
    if args.dry_run:
        cfg.dry_run = True
    return run(cfg)


if __name__ == "__main__":
    raise SystemExit(main())
