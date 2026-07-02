from core.safe_web_scanner import LinkFormParser, parameter_kind, replace_param, same_scope


def test_parameter_kind_classifies_common_security_review_params():
    assert parameter_kind("redirect_uri") == "redirect-like"
    assert parameter_kind("callback_url") == "url-like"
    assert parameter_kind("file") == "file-like"
    assert parameter_kind("user_id") == "id-like"
    assert parameter_kind("q") == "search-like"
    assert parameter_kind("theme") == "generic"


def test_replace_param_preserves_other_query_values():
    url = replace_param("https://example.com/search?q=old&page=1", "q", "safe_canary")
    assert "q=safe_canary" in url
    assert "page=1" in url


def test_scope_check_blocks_other_hosts_but_allows_subdomains_when_enabled():
    assert same_scope("https://example.com/a", "example.com") is True
    assert same_scope("https://evil.example.net/a", "example.com") is False
    assert same_scope("https://api.example.com/a", "example.com") is False
    assert same_scope("https://api.example.com/a", "example.com", include_subdomains=True) is True


def test_html_parser_extracts_links_forms_scripts_and_inline_routes():
    html = """
    <html>
      <a href='/search?q=test'>Search</a>
      <script src='/app.js'></script>
      <script>fetch('/api/users?id=1')</script>
      <form method='GET' action='/find'>
        <input name='q' value='demo'>
        <select name='type'></select>
      </form>
    </html>
    """
    parser = LinkFormParser("https://example.com/")
    parser.feed(html)
    assert "https://example.com/search?q=test" in parser.links
    assert "https://example.com/app.js" in parser.scripts
    assert "fetch('/api/users?id=1')" in parser.inline_script
    assert len(parser.forms) == 1
    assert parser.forms[0].action_url == "https://example.com/find"
    assert parser.forms[0].parameters["q"] == "demo"
    assert "type" in parser.forms[0].parameters
