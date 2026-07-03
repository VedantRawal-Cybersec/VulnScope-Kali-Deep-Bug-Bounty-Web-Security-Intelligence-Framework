from core.ai_planner import AIPlanner
from core.crawler_v2 import HtmlRouteParser, extract_inline_routes, same_scope
from core.parameter_inventory import param_kind, replace_param
from core.scan_state import ParamRecord, ScanState


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
