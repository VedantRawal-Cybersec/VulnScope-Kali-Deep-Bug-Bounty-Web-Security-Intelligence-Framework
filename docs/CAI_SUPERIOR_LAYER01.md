# CAI Superior Layer 0–1 Implementation

This implementation adds the first CAI Superior execution layer directly into VulnScope's main workflow.

## Layer 0 — System Initialization & Target Profiler

Implemented in:

- `cai_target_profiler_cli.py`
- `cai_scope_guard.py`
- `cai_error_handler.py`

Outputs:

- `reports/output/cai-superior/<domain>/target-profile.json`
- `reports/output/cai-superior/<domain>/target-profile.md`
- `reports/output/cai-superior/<domain>/checkpoint-0.json`

Captured profile signals:

- normalized target and host,
- explicit scope policy,
- DNS IP inventory,
- WHOIS summary when the system tool is available,
- ASN lookup when the system tool is available,
- WAF/CDN heuristic based on passive metadata,
- production/staging classification warning,
- TLS certificate fingerprint using a minimal non-destructive handshake.

## Layer 1 — Reconnaissance & Asset Discovery Agent

Implemented in:

- `cai_recon_agent_cli.py`
- `cai_asset_graph.py`

Outputs:

- `reports/output/cai-superior/<domain>/recon-agent.json`
- `reports/output/cai-superior/<domain>/recon-agent.md`
- `reports/output/cai-superior/<domain>/checkpoint-1.json`
- `reports/output/cai-superior/<domain>/asset-graph.json`
- `reports/output/cai-superior/<domain>/asset-graph.md`

Passive collectors:

- `subfinder` when installed,
- `assetfinder` when installed,
- `amass enum -passive` when installed,
- certificate transparency through `crt.sh`,
- historical URL import through `gau` and `waybackurls` when installed,
- Common Crawl index lookup when reachable,
- placeholder-safe status tracking for repository and aggregator integrations when API keys are not configured.

## Main Workflow Integration

`kai_safe_interface.py` now runs CAI Superior Layer 0–1 automatically after authorization and target isolation, before dashboard selection.

Skip switch:

```bash
VULNSCOPE_SKIP_CAI_SUPERIOR=1 python3 main.py
```

Direct run:

```bash
python3 cai_superior_cli.py --target https://example.com
```

## Safety Behavior

- The layer does not modify production data.
- It does not send exploit payloads.
- It does not perform brute force discovery.
- It handles missing tools, timeouts, and network failures as structured `handled_error` records.
- It continues safely when optional passive collectors are unavailable.

## Validation

```bash
python3 -m py_compile \
  cai_error_handler.py \
  cai_scope_guard.py \
  cai_asset_graph.py \
  cai_target_profiler_cli.py \
  cai_recon_agent_cli.py \
  cai_superior_cli.py \
  kai_safe_interface.py \
  download_data_bundle_cli.py

python3 -m pytest tests/test_cai_superior_layer01.py -q
```
