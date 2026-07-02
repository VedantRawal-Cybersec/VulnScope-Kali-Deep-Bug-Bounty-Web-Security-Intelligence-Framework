from core.tool_orchestrator import CATEGORY_TOOLS, STATUS_VALUES, UltimateToolOrchestrator, build_tool_registry


def test_registry_has_exactly_100_tools_and_required_fields():
    registry = build_tool_registry()
    assert len(registry) == 100
    assert sum(len(items) for items in CATEGORY_TOOLS.values()) == 100
    for tool in registry:
        assert tool.tool_id.startswith("tool_")
        assert tool.tool_name
        assert tool.category
        assert tool.enabled is True
        assert tool.safety_level in {"passive", "safe_active", "lab_only"}
        assert tool.required_scan_mode in {"passive", "safe-active", "lab"}
        assert tool.input_schema
        assert tool.output_schema
        assert tool.timeout > 0
        assert tool.rate_limit
        assert tool.run_function
        assert tool.status in STATUS_VALUES
        assert tool.error_handler == "capture_error_continue_scan"


def test_passive_mode_skips_safe_active_tools_without_marking_completed():
    orchestrator = UltimateToolOrchestrator("https://example.com", scan_mode="passive")
    registry = build_tool_registry()
    safe_active = [tool for tool in registry if tool.required_scan_mode == "safe-active"]
    assert safe_active
    for tool in safe_active:
        result = orchestrator._run_one(tool, 1, 100)
        assert result.status == "skipped"
        assert "requires safe-active" in result.skipped_reason


def test_payload_counts_all_statuses():
    orchestrator = UltimateToolOrchestrator("https://example.com", scan_mode="passive")
    orchestrator.results = []
    payload = orchestrator.payload()
    assert payload["tool_count"] == 100
    for status in STATUS_VALUES:
        assert status in payload["status_counts"]
    assert payload["safety"]["skipped_tools_not_marked_completed"] is True
    assert payload["safety"]["failed_tools_do_not_create_findings"] is True
