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
    assert "VULNSCOPE ULTIMATE" in text
    assert "Domain:" in text
    assert "Full Request:" in text
    assert "Endpoint:" in text
    assert "Path:" in text
    assert "Parameters:" in text
    assert "Safe string under test:" in text
    assert "Evidence snippet:" in text


def test_detailed_final_dashboard_fields_and_reports(tmp_path):
    dashboard = LiveDashboard("https://example.com/api/users?id=1", enabled=False, interactive=False)
    dashboard.add_finding(
        "Evidence Review Lead",
        "A safe evidence module produced a review-ready security signal.",
        "HIGH",
        url="https://example.com/api/users?id=1",
        parameter="id=1",
        test_string="safe-actuator:evidence_review",
        evidence="status=confirmed confidence=high",
        cvss="Pending CVSS scoring",
        confidence="High evidence confidence",
        reproduction="1. Open react-run.md\n2. Review generated evidence\n3. Validate only inside authorized scope",
        confirmation="confirmed",
    )
    final_text = dashboard.final_text(color=False)
    assert "VULNSCOPE ULTIMATE" in final_text
    assert "FINAL KALI CLI DASHBOARD" in final_text
    assert "Severity Summary:" in final_text
    assert "CRITICAL:" in final_text
    assert "HIGH:" in final_text
    assert "MEDIUM:" in final_text
    assert "LOW:" in final_text
    assert "WHAT:" in final_text
    assert "WHY:" in final_text
    assert "WHERE:" in final_text
    assert "TESTED EVIDENCE:" in final_text
    assert "REPRODUCTION / VALIDATION STEPS:" in final_text
    assert "Confirmed Findings:" in final_text
    paths = dashboard.write_reports(tmp_path)
    assert Path(paths["cli_final_dashboard_md"]).exists()
    assert Path(paths["cli_final_dashboard_json"]).exists()
    assert Path(paths["cli_session_json"]).exists()
    assert Path(paths["detailed_findings_json"]).exists()


def test_dashboard_redacts_sensitive_strings_in_report(tmp_path):
    dashboard = LiveDashboard("https://example.com/api?token=secret-value", enabled=False, interactive=False)
    dashboard.update(evidence="api_key=super-secret-value token=hidden")
    paths = dashboard.write_reports(tmp_path)
    md_text = Path(paths["cli_final_dashboard_md"]).read_text()
    assert "api_key=<redacted>" in md_text
    assert "token=<redacted>" in md_text
    assert "super-secret-value" not in md_text
