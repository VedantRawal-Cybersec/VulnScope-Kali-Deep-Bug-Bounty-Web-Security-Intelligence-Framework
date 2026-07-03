from core.scan_quality import ScanQualityGate
from core.scan_state import ParamRecord, ScanState
from core.test_queue import TestQueueBuilder
from core.tool_router import ToolRouter


def test_test_queue_builder_creates_passive_classification_tests():
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=test", name="q", value="test", kind="search-like", risk_score=80))
    summary = TestQueueBuilder(state=state, scan_mode="passive", max_params=10).build()
    assert summary.parameters_considered == 1
    assert summary.passive_tests >= 1
    assert summary.blocked_by_mode == 1
    assert any(test.test_name == "classification_review" for test in state.tests.values())


def test_test_queue_builder_adds_safe_active_canary_tests():
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=test", name="q", value="test", kind="search-like", risk_score=80))
    summary = TestQueueBuilder(state=state, scan_mode="safe-active", max_params=10).build()
    assert summary.safe_active_parameters == 1
    assert any(test.test_name == "reflection_canary" for test in state.tests.values())


def test_quality_gate_flags_params_without_tests():
    state = ScanState("https://example.com", resume=False)
    for idx in range(3):
        state.add_url(f"https://example.com/page{idx}", depth=1, source="test").status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=test", name="q", value="test", kind="search-like", risk_score=80))
    state.stats["request_budget_total"] = 20
    router = ToolRouter()
    result = ScanQualityGate(state=state, ollama={"ok": False, "generation_status": "skipped"}, tool_matrix=router.matrix()).evaluate()
    codes = {issue.code for issue in result.issues}
    assert result.grade == "LOW"
    assert "PARAMS_WITHOUT_TESTS" in codes


def test_tool_router_records_completed_output_counts():
    router = ToolRouter()
    router.started("crawler_v2")
    router.completed("crawler_v2", output_count=42, reason="urls discovered")
    matrix = router.matrix()
    assert matrix["counts"]["completed"] >= 1
    crawler = [tool for tool in matrix["tools"] if tool["tool_id"] == "crawler_v2"][0]
    assert crawler["output_count"] == 42
