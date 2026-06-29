#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

STATE = Path("reports/output/control-center/state.json")
EVENTS = Path("reports/output/control-center/events.jsonl")
ARTEMIS = Path("reports/output/artemis/run/artemis-run.json")
EVIDENCE = Path("reports/output/evidence-cards/evidence-cards.json")
REPORTABILITY = Path("reports/output/reportability/reportability.json")
CONFIG = Path("autonomous_control_config.yaml")
RUN_LOCK = threading.Lock()
CURRENT_PROCESS: subprocess.Popen | None = None

HTML = r"""
<!doctype html>
<html>
<head>
  <title>VulnScope Control Center</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { --bg:#05070d; --panel:#0c1220; --panel2:#10192b; --line:#26364f; --text:#eaf2ff; --muted:#8ba3c7; --cyan:#59e6ff; --green:#59ff9c; --amber:#ffd166; --red:#ff5d73; }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(circle at top left,#15203a 0,#05070d 36%,#02030a 100%); color:var(--text); font-family:Inter,Segoe UI,Arial,sans-serif; }
    .layout { display:grid; grid-template-columns:280px 1fr; min-height:100vh; }
    .side { border-right:1px solid var(--line); background:linear-gradient(180deg,#09101d,#05070d); padding:22px; position:sticky; top:0; height:100vh; }
    .brand { font-size:22px; font-weight:800; letter-spacing:2px; color:var(--cyan); }
    .sub { color:var(--muted); font-size:12px; margin-top:6px; line-height:1.5; }
    .pill { border:1px solid var(--line); background:#0a1323; padding:10px 12px; border-radius:12px; margin:14px 0; font-size:12px; color:var(--muted); }
    .main { padding:24px; }
    .top { display:flex; justify-content:space-between; gap:16px; align-items:center; margin-bottom:18px; }
    .title { font-size:30px; font-weight:800; letter-spacing:.5px; }
    .buttons { display:flex; gap:10px; flex-wrap:wrap; }
    button { border:1px solid var(--line); background:#0e2038; color:var(--text); padding:11px 14px; border-radius:12px; cursor:pointer; font-weight:700; }
    button.primary { background:linear-gradient(90deg,#0c9bb5,#1457ff); border-color:#3bdfff; }
    button:hover { filter:brightness(1.14); }
    .grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; }
    .card { background:linear-gradient(180deg,rgba(17,28,50,.95),rgba(7,12,23,.95)); border:1px solid var(--line); border-radius:18px; padding:16px; box-shadow:0 20px 50px rgba(0,0,0,.25); }
    .metric { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }
    .value { font-size:27px; font-weight:800; margin-top:8px; }
    .ok { color:var(--green); } .warn { color:var(--amber); } .bad { color:var(--red); } .cyan { color:var(--cyan); }
    .wide { grid-column:span 2; }
    .full { grid-column:1/-1; }
    .timeline { max-height:340px; overflow:auto; padding-right:6px; }
    .event { border-left:3px solid var(--cyan); padding:8px 0 8px 12px; margin:8px 0; color:#dce9ff; }
    .event small { color:var(--muted); display:block; margin-top:3px; }
    table { width:100%; border-collapse:collapse; }
    td,th { text-align:left; border-bottom:1px solid #1e2b42; padding:10px 8px; font-size:13px; vertical-align:top; }
    th { color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:1px; }
    code { color:#9fefff; word-break:break-all; }
    .console { background:#030711; border:1px solid #1d2b46; border-radius:14px; padding:14px; max-height:360px; overflow:auto; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#bfe3ff; font-size:12px; white-space:pre-wrap; }
    .scope { color:var(--amber); font-size:12px; margin-top:18px; line-height:1.55; }
    @media(max-width:1000px){ .layout{grid-template-columns:1fr}.side{height:auto;position:relative}.grid{grid-template-columns:1fr}.wide{grid-column:span 1} }
  </style>
</head>
<body>
<div class="layout">
  <aside class="side">
    <div class="brand">VULNSCOPE</div>
    <div class="sub">Autonomous Control Center<br/>Safe authorized-only mode</div>
    <div class="pill">Status: <b id="runStatus" class="cyan">loading</b></div>
    <div class="pill">Config: <code>autonomous_control_config.yaml</code></div>
    <div class="scope"><b>Boundary</b><br/>No exploit execution, no stealth, no credential dumping, no destructive fuzzing, no state-changing requests.</div>
  </aside>
  <main class="main">
    <div class="top">
      <div><div class="title">Mission Control</div><div class="sub">Think → Plan → Correlate → Report</div></div>
      <div class="buttons">
        <button class="primary" onclick="runOnce()">Run Autonomous Cycle</button>
        <button onclick="refresh()">Refresh</button>
      </div>
    </div>
    <section class="grid">
      <div class="card"><div class="metric">Running</div><div class="value" id="running">-</div></div>
      <div class="card"><div class="metric">Targets</div><div class="value" id="targets">-</div></div>
      <div class="card"><div class="metric">Events</div><div class="value" id="eventsCount">-</div></div>
      <div class="card"><div class="metric">Findings</div><div class="value" id="findingsCount">-</div></div>
      <div class="card wide"><h3>Current Phase</h3><div id="phase" class="console">-</div></div>
      <div class="card wide"><h3>JARVIS Next Action</h3><div id="nextAction" class="console">-</div></div>
      <div class="card wide"><h3>Mission Events</h3><div class="timeline" id="events"></div></div>
      <div class="card wide"><h3>Top Review Items</h3><table><thead><tr><th>Type</th><th>Where</th><th>Why</th></tr></thead><tbody id="findings"></tbody></table></div>
      <div class="card full"><h3>Last Run Targets</h3><table><thead><tr><th>Target</th><th>Allowed</th><th>Phases</th><th>Status</th></tr></thead><tbody id="targetRows"></tbody></table></div>
    </section>
  </main>
</div>
<script>
async function api(path, opts){ const r = await fetch(path, opts || {}); return await r.json(); }
function esc(x){ return String(x ?? '').replace(/[&<>]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[s])); }
async function runOnce(){ await api('/api/run-once',{method:'POST'}); setTimeout(refresh,800); }
async function refresh(){
  const data = await api('/api/status');
  const s = data.state || {}; const ev = data.events || []; const findings = data.findings || [];
  document.getElementById('runStatus').textContent = s.running ? 'ACTIVE' : 'IDLE';
  document.getElementById('running').innerHTML = s.running ? '<span class="ok">ACTIVE</span>' : '<span class="warn">IDLE</span>';
  document.getElementById('targets').textContent = (s.targets || []).length || (s.config?.targets || []).length || 0;
  document.getElementById('eventsCount').textContent = ev.length;
  document.getElementById('findingsCount').textContent = findings.length;
  document.getElementById('phase').textContent = JSON.stringify(s.current_phase || {}, null, 2);
  document.getElementById('nextAction').textContent = data.next_action || 'Run a cycle to generate next action.';
  document.getElementById('events').innerHTML = ev.slice(-80).reverse().map(e => `<div class="event"><b>${esc(e.type)}</b><small>${new Date((e.ts||0)*1000).toLocaleString()} · ${esc(e.level)}</small><small>${esc(JSON.stringify(e.payload||{}).slice(0,280))}</small></div>`).join('');
  document.getElementById('findings').innerHTML = findings.slice(0,25).map(f => `<tr><td>${esc(f.type||f.title||f.category||'review')}</td><td><code>${esc(f.where||f.url||f.endpoint||'n/a')}</code></td><td>${esc(f.reason||f.why_flagged||f.safe_next_step||'Evidence correlation')}</td></tr>`).join('');
  const rows = s.targets || s.last_run?.targets || [];
  document.getElementById('targetRows').innerHTML = rows.map(t => `<tr><td><code>${esc(t.target)}</code></td><td>${t.allowed ? '<span class="ok">yes</span>' : '<span class="bad">no</span>'}</td><td>${(t.phases||[]).length}</td><td>${esc(t.reason||((t.phases||[]).every(p=>p.ok)?'ok':'review'))}</td></tr>`).join('');
}
setInterval(refresh,5000); refresh();
</script>
</body>
</html>
"""


def load_json(path: Path) -> Any:
    if not path.exists():
        return {} if path.suffix == ".json" else []
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def load_events(limit: int = 200) -> list[dict[str, Any]]:
    if not EVENTS.exists():
        return []
    rows = []
    for line in EVENTS.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


def collect_findings() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    evidence = load_json(EVIDENCE)
    if isinstance(evidence, dict):
        rows.extend([x for x in (evidence.get("cards") or evidence.get("candidates") or []) if isinstance(x, dict)])
    reportability = load_json(REPORTABILITY)
    if isinstance(reportability, dict):
        rows.extend([x for x in reportability.get("candidates", []) if isinstance(x, dict)])
    artemis = load_json(ARTEMIS)
    if isinstance(artemis, dict):
        for t in artemis.get("targets", []):
            if isinstance(t, dict):
                rows.append({"type": "ARTEMIS_TARGET_SUMMARY", "where": t.get("target"), "reason": str(t.get("decision", {})), "safe_next_step": "Review ARTEMIS report."})
    return rows[:120]


def next_action(state: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if state.get("running"):
        phase = state.get("current_phase") or {}
        return f"Current phase: {phase.get('label', 'working')} on {phase.get('target', 'target')}. Let the cycle complete."
    if not state.get("last_run"):
        return "No completed autonomous cycle yet. Press Run Autonomous Cycle."
    if not findings:
        return "Low evidence. Run ARTEMIS passive mode, public search, and advanced correlation again."
    return "Review the top evidence cards, validate only authorized findings manually, then generate the final report."


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def status():
    state = load_json(STATE)
    events = load_events()
    findings = collect_findings()
    return jsonify({"state": state, "events": events, "findings": findings, "next_action": next_action(state if isinstance(state, dict) else {}, findings)})


@app.route("/api/run-once", methods=["POST"])
def run_once():
    global CURRENT_PROCESS
    with RUN_LOCK:
        if CURRENT_PROCESS and CURRENT_PROCESS.poll() is None:
            return jsonify({"started": False, "reason": "already running"})
        CURRENT_PROCESS = subprocess.Popen(["python3", "autonomous_control_daemon.py", "--config", str(CONFIG), "--once"])
    return jsonify({"started": True, "pid": CURRENT_PROCESS.pid})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
