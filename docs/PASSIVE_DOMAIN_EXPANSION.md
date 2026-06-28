# Passive Domain Expansion

Passive Domain Expansion finds subdomains and archived URLs before deeper testing.

It is designed to improve coverage while staying controlled:

- passive crt.sh lookup
- optional local subfinder enrichment
- optional gau and waybackurls archived URL collection
- high-value URL candidate classification
- optional approved passive scan of discovered subdomains

## Run Passive Expansion

```bash
python3 domain_recon_cli.py --target example.com
```

For a full URL:

```bash
python3 domain_recon_cli.py --target https://www.example.com
```

Use crt.sh only:

```bash
python3 domain_recon_cli.py --target example.com --no-tools
```

## Outputs

```text
reports/output/recon/domain-expansion.md
reports/output/recon/domain-expansion.json
reports/output/recon/subdomains.txt
reports/output/recon/archived-urls.txt
reports/output/recon/high-value-urls.json
```

## High-Value URL Signals

The classifier highlights archived URLs that look like:

- API routes
- auth/session routes
- admin/dashboard routes
- object/account/order routes
- interesting files such as `.js`, `.map`, `.json`, `.xml`, `.bak`, `.old`
- redirect/state parameters
- ID/object parameters

These are review candidates, not confirmed vulnerabilities.

## Optional Subdomain Scanning

Only use this if every discovered subdomain is authorized and in scope.

```bash
python3 domain_recon_cli.py --target example.com --scan-discovered --max-subdomains 10
```

The tool asks for explicit confirmation before scanning discovered subdomains.

## Recommended Full Workflow

```bash
python3 domain_recon_cli.py --target example.com
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --full
python3 ai_discovery_cli.py --input reports/output/recon/domain-expansion.json
python3 mythic_uplift_cli.py --input reports/output/recon/domain-expansion.json
```

## Safety Boundary

Passive expansion is allowed for authorized assessment workflows. Active scanning across discovered subdomains requires explicit scope confirmation.
