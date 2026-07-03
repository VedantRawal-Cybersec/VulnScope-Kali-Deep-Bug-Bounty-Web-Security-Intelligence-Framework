from core.ai_planner import AIPlanner
from core.cai_react_engine import ReactDecision, SafeCAIReactAgent
from core.crawler_v2 import HtmlRouteParser, extract_inline_routes, same_scope
from core.parameter_inventory import param_kind, replace_param
from core.scan_state import ParamRecord, ScanState


class _LLMResponse:
    def __init__(self, parsed):
        self.ok = True
        self.parsed = parsed


class _FakeLLM:
    def __init__(self, parsed):
        self.parsed = parsed
        self.calls = 0

    def chat_json(self, **kwargs):
        self.calls += 1
        return _LLMResponse(self.parsed)


class _FakeClient:
    def budget_remaining(self):
        return 10


class _FakeTester:
    client = _FakeClient()


def test_parameter_inventory_v2_classifies_and_replaces_values(tmp_path, monkeypatch):
    assert param_kind("redirect_uri") == "route-like"
    assert param_kind("callback_url") == "reference-like"
    assert param_kind("file") == "resource-like"
    assert param_kind("user_id") == "object-like"
    assert param_kind("q") == "search-like"
    url = replace_param("https://example.com/search?q=old&page=1", "q", "vs_canary")
    assert "q=vs_canary" in url
    assert "page=1" in url


def test_html_route_parser_extracts_routes_forms_and_scripts():
    html = """
    <html>
      <a href='/search?q=test'>Search</a>
      <script src='/app.js'></script>
      <script>fetch('/api/users?id=1')</script>
      <form method='GET' action='/find'>
        <input name='q' value='demo'>
      </form>
    </html>
    """
    parser = HtmlRouteParser("https://example.com/")
    parser.feed(html)
    assert "https://example.com/search?q=test" in parser.links
    assert "https://example.com/app.js" in parser.scripts
    assert len(parser.forms) == 1
    routes = extract_inline_routes(parser.inline_script, "https://example.com/")
    assert "https://example.com/api/users?id=1" in routes


def test_scope_rules_are_same_scope_only_with_landing_host_support():
    assert same_scope("https://example.com/a", "example.com") is True
    assert same_scope("https://api.example.com/a", "example.com") is False
    assert same_scope("https://api.example.com/a", "example.com", include_subdomains=True) is True
    assert same_scope("https://www.example.com/a", "example.com", extra_hosts={"www.example.com"}) is True
    assert same_scope("https://evil.example.net/a", "example.com", extra_hosts={"www.example.com"}) is False


def test_ai_planner_fallback_prefers_parameter_testing(monkeypatch, tmp_path):
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=x", name="q", value="x", kind="search-like", risk_score=70))
    planner = AIPlanner(ollama_url="http://127.0.0.1:9/api/generate", timeout=1)
    decision = planner.decide(state)
    assert decision.action in {"test_parameter", "review_scripts", "write_reports"}


def _agent(state, llm=None, scan_mode="safe-active", monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setenv("VULNSCOPE_DISABLE_LLM_PLANNER", "1")
    return SafeCAIReactAgent(
        target="https://example.com",
        scan_mode=scan_mode,
        state=state,
        crawler=object(),
        tester=_FakeTester(),
        llm=llm or _FakeLLM({"tool": "summarize_surface", "arguments": {}, "confidence": 70}),
        dashboard=None,
        trace=None,
        turns=None,
        tool_router=None,
        max_turns=5,
        max_params=20,
    )


def test_cai_react_decision_rejects_unsupported_tools():
    decision = ReactDecision(
        reasoning="try unsupported external tool",
        tool="unsupported_external_tool",
        arguments={"url": "https://example.com/search?q=x"},
        confidence=90,
        source="ollama",
    ).safe(scan_mode="safe-active")
    assert decision.tool == "stop"
    assert decision.confidence == 0


def test_cai_react_passive_mode_forces_classification_only():
    decision = ReactDecision(
        reasoning="review a reflected parameter safely",
        tool="test_parameter",
        arguments={"url": "https://example.com/search?q=x", "parameter": "q", "test_name": "reflection_canary"},
        confidence=90,
        source="ollama",
    ).safe(scan_mode="passive")
    assert decision.tool == "test_parameter"
    assert decision.arguments["test_name"] == "classification_review"


def test_cai_react_binds_llm_parameter_request_to_discovered_input(monkeypatch, tmp_path):
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=x", name="q", value="x", kind="search-like", risk_score=80))
    llm = _FakeLLM(
        {
            "reasoning": "test a parameter, but the model supplied an invented target",
            "tool": "test_parameter",
            "arguments": {"url": "https://evil.example/search?q=x", "parameter": "q", "test_name": "reflection_canary"},
            "confidence": 99,
        }
    )
    agent = _agent(state, llm=llm, monkeypatch=monkeypatch)
    monkeypatch.delenv("VULNSCOPE_DISABLE_LLM_PLANNER", raising=False)
    decision = agent.decide()
    assert decision.tool == "test_parameter"
    assert decision.arguments["url"] == "https://example.com/search?q=x"
    assert decision.arguments["parameter"] == "q"


def test_parameter_progression_does_not_repeat_reflection(monkeypatch, tmp_path):
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    param = ParamRecord(url="https://example.com/search?q=x", name="q", value="x", kind="search-like", risk_score=80)
    state.add_param(param)
    agent = _agent(state, monkeypatch=monkeypatch)
    first = agent.decide()
    assert first.arguments["test_name"] == "reflection_canary"
    param.tested.append("reflection_canary")
    param.status = "review"
    second = agent.decide()
    assert second.tool == "test_parameter"
    assert second.arguments["test_name"] == "classification_review"
    param.tested.append("classification_review")
    third = agent.decide()
    assert third.tool == "write_reports"


def test_object_like_parameters_get_classification_only(monkeypatch, tmp_path):
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/api/user?id=1", name="id", value="1", kind="object-like", risk_score=90))
    agent = _agent(state, monkeypatch=monkeypatch)
    decision = agent.decide()
    assert decision.tool == "test_parameter"
    assert decision.arguments["test_name"] == "classification_review"


def test_llm_is_paced_not_called_every_turn(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSCOPE_LLM_DECISION_INTERVAL", "3")
    state = ScanState("https://example.com", resume=False)
    state.urls["https://example.com/"].status = "done"
    state.add_param(ParamRecord(url="https://example.com/search?q=x", name="q", value="x", kind="search-like", risk_score=80))
    llm = _FakeLLM({"tool": "test_parameter", "arguments": {"url": "https://example.com/search?q=x", "parameter": "q", "test_name": "reflection_canary"}, "confidence": 90})
    agent = SafeCAIReactAgent(
        target="https://example.com",
        scan_mode="safe-active",
        state=state,
        crawler=object(),
        tester=_FakeTester(),
        llm=llm,
        dashboard=None,
        trace=None,
        turns=None,
        tool_router=None,
        max_turns=5,
        max_params=20,
    )
    agent.decide()
    agent.decide()
    assert llm.calls == 1
