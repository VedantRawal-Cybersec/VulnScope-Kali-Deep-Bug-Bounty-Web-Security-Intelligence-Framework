#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

RUN = Path("reports/output/artemis/run/artemis-run.json")
KG = Path("reports/output/artemis/knowledge/knowledge-graph.json")

HTML = """
<!doctype html>
<html>
<head>
  <title>ARTEMIS Passive Intelligence</title>
  <meta http-equiv="refresh" content="15">
  <style>
    body { background:#080b12; color:#e8f2ff; font-family:Arial, sans-serif; padding:24px; }
    .card { background:#121827; border:1px solid #263247; border-radius:14px; padding:18px; margin:14px 0; }
    .risk-HIGH { color:#ff5f5f; font-weight:bold; }
    .risk-MEDIUM { color:#ffd166; font-weight:bold; }
    .risk-LOW { color:#7bd88f; font-weight:bold; }
    code { color:#8bd3ff; }
  </style>
</head>
<body>
<h1>ARTEMIS Passive Autonomous Intelligence</h1>
<p><b>FOR AUTHORIZED SECURITY TESTING ONLY – PASSIVE / NON-DESTRUCTIVE MODE.</b></p>
<div class="card">
  <h2>Last Run</h2>
  <p>Seconds: <code>{{ run.get('seconds', 'n/a') }}</code></p>
  <p>Scope policy: <code>{{ run.get('scope_policy', 'n/a') }}</code></p>
</div>
{% for t in run.get('targets', []) %}
<div class="card">
  <h2>{{ t.target }}</h2>
  <p>Decision: <code>{{ t.decision.action }}</code> — {{ t.decision.reason }}</p>
  <p>Hosts: <code>{{ t.intel_summary.hosts }}</code> | URLs: <code>{{ t.intel_summary.wayback_urls }}</code> | Predictions: <code>{{ t.prediction_summary.predictions }}</code></p>
  <p>Risk: <span class="risk-{{ t.report.risk }}">{{ t.report.risk }}</span> score=<code>{{ t.report.risk_score }}</code></p>
</div>
{% endfor %}
<div class="card">
  <h2>Strategy Weights</h2>
  {% for k,v in run.get('strategy_weights', {}).items() %}<p><code>{{ k }}</code>: {{ v }}</p>{% endfor %}
</div>
</body>
</html>
"""


def load(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


@app.route("/")
def index():
    return render_template_string(HTML, run=load(RUN), kg=load(KG))


@app.route("/api/status")
def status():
    return jsonify({"run": load(RUN), "knowledge": load(KG)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
