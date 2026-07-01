from pathlib import Path

from core.live_dashboard import LiveDashboard, target_components


def test_target_components_extracts_domain_path_and_query():
    parts = target_components("example.com/api/users?id=1&mode=readonly")
    assert parts["target"] == "https://example.com/api/users?id=1&mode=readonly"
    assert parts["domain"] == "example.com"
    assert parts["path"] == "/api/users"
    assert parts["parameters"] == "id=1&mode=readonly"
    assert parts["request_line"] == "GET /api/users?id=1&mode=readonly"


def test_dashboard_renders_required_visibility_fields():
    dashboard = LiveDashboard("https://example.com/search?q=demo", enabled=False, interactive=False)
    dashboard.update(
        phase="Passive reconnaissance",
        phase_progress=50,
        requests=3,
        findings=1,
        action="Running passive endpoint review",
        probe_string="safe-actuator:passive_recon",
        hypothesis="Passive evidence collection only",
        evidence="status=completed",
    )
    text = dashboard.render_text(color=False)
    assert "Domain:" in text
    assert "Endpoint:" in text
    assert "Path:" in text
    assert "Parameters:" in text
    assert "String under test:" in text
    assert "Evidence snippet:" in text


def test_dashboard_redacts_sensitive_strings_in_report(tmp_path):
    dashboard = LiveDashboard("https://example.com/api?token=secret-value", enabled=False, interactive=False)
    dashboard.update(evidence="api_key=super-secret-value token=hidden")
    paths = dashboard.write_reports(tmp_path)
    md_text = Path(paths["live_dashboard_md"]).read_text()
    assert "api_key=<redacted>" in md_text
    assert "token=<redacted>" in md_text
    assert "super-secret-value" not in md_text
