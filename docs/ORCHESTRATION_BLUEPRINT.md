# VulnScope Orchestration Blueprint

VulnScope's product goal is a one-command, consent-gated security assessment workflow for owned or explicitly authorized websites.

## User experience

The normal user should only need:

```bash
python3 vulnscope_deep.py https://owned-site.com
```

Then VulnScope asks for authorization, checks reachability, and runs a deep safe-active workflow using internal defaults. Advanced flags still exist, but they are not required for normal use.

## Required workflow

1. Authorization gate
   - Written authorization confirmation is required unless an operator uses `--yes` after already confirming consent.

2. Reachability gate
   - DNS, TCP, HTTP, and curl checks run before the scan.
   - If the target is unreachable, VulnScope stops instead of pretending a zero-finding scan is meaningful.

3. Scope model
   - Default scope is exact target host plus same parent-domain subdomains when discovered.
   - Out-of-scope seed URLs are ignored.

4. Recon and liveness
   - Discover candidate subdomains using installed/registered tools and passive sources where available.
   - Filter for alive hosts before deeper crawling.

5. Deep discovery
   - Crawl same-scope pages.
   - Use browser crawling when available.
   - Parse public discovery documents.
   - Mine JavaScript files for routes and endpoints.
   - Extract forms and query parameters.
   - Build parameter inventory with risk scoring.

6. Validation-first scheduling
   - In `safe-active` and `lab` modes, discovered or seeded query parameters are validated before the engine exhausts the crawl queue.
   - This prevents validation starvation.

7. Dynamic tools
   - External tools are registered through `tools/registry.json` and repaired from `./tools/`.
   - Tools only run when registered, enabled, approved, and scoped.
   - Stdout/stderr are captured and parsed into findings or manual-review leads.

8. AI assistance
   - LLM reasoning is advisory.
   - The deterministic scheduler owns execution and safety.
   - LLM output cannot authorize out-of-scope, credential, destructive, or data-modifying behavior.

9. Reporting
   - Final report includes coverage, discovered URLs, parameters, tool status, findings, manual-review leads, and network diagnostics.

## Seed URLs

Some owned applications hide important routes behind login, JavaScript, or private navigation. Operators can provide seed URLs:

```bash
python3 vulnscope_deep.py https://owned-site.com \
  --seed-url '/search?q=test' \
  --seed-url '/product?id=1'
```

Seed URLs are normal application URLs with existing query parameters. They are not attack payloads.

## Future authenticated testing

Two-account authorization testing can be added later, but must use a separate auth profile file and never store credentials in git.

Planned profile shape:

```json
{
  "target": "https://owned-site.com",
  "account_a": {
    "label": "low_priv_user_a",
    "storage_state_file": "secrets/account_a_state.json"
  },
  "account_b": {
    "label": "low_priv_user_b",
    "storage_state_file": "secrets/account_b_state.json"
  },
  "allowed_tests": ["access-control-differential-review"]
}
```

Only owned/authorized environments should use this.

## Non-goals

VulnScope core does not include destructive payloads, credential attacks, data exfiltration, reverse shells, or target data modification. External tools remain approval-gated and scoped.
