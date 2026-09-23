# Recommended MCP Contracts

bounty-brain:
brain_target_summary, brain_assets, brain_endpoints, brain_roles, brain_objects, brain_workflows, brain_states, brain_relationships, brain_coverage, brain_unknowns, brain_negative_knowledge, brain_add_observation, brain_add_relationship, brain_add_test_result, brain_get_priority_jobs

scope-gateway:
scope_check_url, scope_check_host, scope_check_redirect, scope_check_method, scope_check_operation, scope_get_program_rules, scope_get_rate_limits, scope_get_allowed_assets

Target-affecting operations fail closed if scope is absent.

burp-bridge:
burp_history_search, burp_request_get, burp_response_get, burp_site_map, burp_find_requests_by_endpoint, burp_find_requests_by_session, burp_compare_requests, burp_compare_responses, burp_replay_authorized, burp_send_controlled_request, burp_scanner_results, burp_session_health, burp_export_evidence

evidence:
evidence_store_request, evidence_store_response, evidence_store_screenshot, evidence_store_browser_state, evidence_store_callback, evidence_link, evidence_hash, evidence_get, evidence_compare

intelligence (read-only research):
intel_lookup_technology, intel_lookup_advisory, intel_search_research, intel_get_technique, intel_recent_changes

Research can generate controlled test jobs but never bypass the scope gateway.