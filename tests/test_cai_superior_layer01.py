from cai_asset_graph import build_asset_graph
from cai_scope_guard import host_from_target, is_allowed_host, normalize_target, slug_from_target
from cai_target_profiler_cli import detect_cdn_waf, production_guess


def test_scope_helpers():
    target = normalize_target("example.com")
    assert target == "https://example.com"
    assert host_from_target(target) == "example.com"
    assert slug_from_target(target) == "example.com"
    assert is_allowed_host("https://example.com/a", "example.com")
    assert not is_allowed_host("https://sub.example.com/a", "example.com")
    assert is_allowed_host("https://sub.example.com/a", "example.com", include_subdomains=True)


def test_production_guess_and_cdn_detection():
    assert production_guess("staging.example.com")["classification"] == "staging_or_test_likely"
    assert production_guess("example.com")["classification"] == "production_likely"
    profile = {"whois": {"name_servers": ["a.ns.cloudflare.com"]}, "dns": {"reverse_dns": {"1.1.1.1": "cloudflare"}}}
    result = detect_cdn_waf(profile)
    assert result["detected"] is True
    assert "Cloudflare" in result["providers"]


def test_asset_graph_builder():
    profile = {
        "host": "example.com",
        "dns": {"ip_addresses": ["93.184.216.34"]},
        "whois": {"name_servers": ["ns1.example.com"]},
        "technologies": ["Cloudflare"],
    }
    recon = {
        "host": "example.com",
        "subdomains": ["www.example.com"],
        "historical_urls": ["https://example.com/a"],
        "collector_status": {"crtsh": {"status": "ok", "detail": "unit-test"}},
    }
    graph = build_asset_graph("https://example.com", profile, recon)
    assert graph["summary"]["domains"] >= 2
    assert graph["summary"]["ips"] == 1
    assert graph["summary"]["urls"] == 1
    assert graph["summary"]["technology_hints"] == 1
