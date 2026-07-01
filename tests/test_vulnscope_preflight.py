from __future__ import annotations

import json
from pathlib import Path

from vulnscope_preflight import _ollama_tags_url, render_report
from vulnscope import normalize_target, host_from_target


def test_ollama_tags_url_from_generate_endpoint():
    assert _ollama_tags_url("http://localhost:11434/api/generate") == "http://localhost:11434/api/tags"


def test_ollama_tags_url_from_base_endpoint():
    assert _ollama_tags_url("http://localhost:11434") == "http://localhost:11434/api/tags"


def test_target_normalization_and_host():
    target = normalize_target("example.com")
    assert target == "https://example.com"
    assert host_from_target(target) == "example.com"


def test_preflight_report_writer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = {
        "ok": True,
        "summary": {"python_missing": 0, "core_tools_missing": 0, "safe_tool_setup": "skipped", "ollama_ready": True, "ollama_model": "qwen2.5:3b"},
        "python_packages": [],
        "core_tools": [],
        "safe_tool_setup": {"ok": True, "status": "skipped"},
        "ollama": {"ok": True, "model": "qwen2.5:3b"},
        "blocking_issues": [],
    }
    render_report(payload)
    report = Path("reports/output/vulnscope-main/preflight.json")
    assert report.exists()
    assert json.loads(report.read_text())["ok"] is True
    assert Path("reports/output/vulnscope-main/preflight.md").exists()
