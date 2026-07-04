# Target Reachability and Seed URLs

If VulnScope reports `status_code: 0`, `ConnectTimeoutError`, or `Max retries exceeded`, the scanner did not reach the target. No vulnerability scanner can produce valid findings when the machine running the scan cannot connect to the site.

## Step 1: Diagnose connectivity

```bash
python3 scripts/network_diag.py --target https://your-owned-site.com
```

The output is written to:

```text
logs/network_diagnostics.json
```

Check:

- DNS resolution
- TCP connection
- HTTP response
- curl response

Fix DNS, proxy, VPN, firewall, or scheme (`http` vs `https`) before expecting findings.

## Step 2: Provide seed URLs for owned apps

If the site is reachable but most routes are hidden behind navigation, JavaScript, login, or admin panels, provide same-scope seed URLs. These are normal application URLs with existing query parameters, not attack payloads.

```bash
python3 scripts/owned_site_scan.py \
  --target https://your-owned-site.com \
  --mode bugbounty \
  --seed-url '/search?q=test' \
  --seed-url '/product?id=1' \
  --max-pages 80 \
  --max-depth 3 \
  --max-actions 120 \
  --request-budget 400
```

VulnScope ignores out-of-scope seed URLs.

## Step 3: Run safe-active validation

In `safe-active` and `lab` mode, VulnScope prioritizes discovered/seeded query parameters before exhausting the crawl queue. This prevents validation starvation while keeping the same safety boundary:

- same-scope only
- written authorization required
- no credential attacks
- no destructive actions
- no target data modification
- harmless canary/classification checks only in core

## Step 4: Verify progress

```bash
cat reports/output/cai-superior/<host>/autonomous-scan-state.json | grep -E 'params_total|tests_total|findings|seed'
cat reports/output/cai-superior/<host>/cai-react-summary.json
cat reports/output/cai-superior/<host>/final-findings-dashboard.txt
```

Expected flow:

```text
Target reachable
  -> crawler + seeds produce URLs/parameters
  -> safe-active validates parameters first
  -> dynamic tools run if registered/enabled/approved
  -> reports show findings or manual review leads
```
