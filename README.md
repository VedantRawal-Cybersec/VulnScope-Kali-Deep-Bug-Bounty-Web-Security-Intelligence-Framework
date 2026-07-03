# VulnScope-Kali

**Deep Bug Bounty Web Security Intelligence Framework for Kali Linux**

VulnScope-Kali is an authorized web security assessment framework designed to combine safe discovery, endpoint intelligence, security header analysis, parameter mapping, evidence correlation, confidence scoring, adaptive knowledge, automation support, and professional reporting.

> This project is built for authorized testing only: owned applications, local labs, CTF environments, and in-scope bug bounty targets where automated testing is permitted by the program policy.

## Current Version

`v1.14.1-lab-review-mode` — Phase-stable deep discovery with explicit lab and bug bounty launcher modes.

## Current Capabilities

Implemented modules:

- Kali-style terminal banner
- Interactive target URL input
- Authorization confirmation
- Passive, safe-active, lab, and bug bounty launcher modes
- URL validation
- Same-domain scope guard
- Deep public asset discovery
- robots.txt and sitemap.xml parsing
- Same-domain crawler
- JavaScript file discovery
- Endpoint extraction from JavaScript text
- Browser-assisted route discovery when `--browser` is enabled
- API surface mapping
- Parameter and form discovery
- Parameter classification and risk scoring
- Access Control / IDOR candidate hints
- Safe reflection canary checks
- Input error-behavior observations
- Redirect behavior review
- Lab-mode enhanced review leads for intentionally vulnerable labs
- OWASP coverage reporting
- Evidence correlation engine
- Finding evidence store
- Markdown, JSON, TXT, and CSV report generation
- CAI-style live CLI dashboard
- Phase runner summary

## Advanced Engines Included as Safe Foundations

- Deep asset discovery engine
- DeepRoute Intelligence Engine
- ParamSense-style parameter intelligence
- API Surface Mapper
- Safe reflection signal module
- Input handling signal module
- Access Control / IDOR hint module
- CORS & Client Trust Analyzer
- Sensitive Exposure Finder
- Evidence Correlation Engine
- Adaptive Learning Knowledge Base
- Controlled external-tool readiness layer for nuclei, katana, httpx, ffuf, dalfox, OWASP ZAP, and restricted lab workflows

## Ethical Guardrails

VulnScope-Kali is designed with safety controls from the beginning:

- Authorization confirmation before scanning
- Same-domain scope lock
- Rate limiting and request budgets
- Request timeout controls
- No brute force
- No credential capture
- No database dumping
- No destructive payloads
- No out-of-scope scanning
- No unknown tool auto-execution
- No automatic activation of risky modules
- No OOB callback injection
- No cloud metadata SSRF probing
- No cache poisoning attempts
- No service-disruptive race-condition or request-smuggling testing
- Safe reflection and input-handling modules are signal-based and non-destructive
- Lab mode is for intentionally vulnerable labs and still avoids destructive behavior

## Installation

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
pip3 install -r requirements.txt
```

## Usage

Interactive mode:

```bash
python3 main.py
```

Direct safe-active URL mode:

```bash
python3 main.py --target https://example.com --yes --scan-mode safe-active --max-pages 80
```

Bug bounty mode shortcut. This keeps low-impact behavior and defaults passive scans to safe-active:

```bash
python3 main.py \
  --mode bugbounty \
  --target https://example.com \
  --yes \
  --browser \
  --max-pages 120 \
  --max-depth 3 \
  --max-params 180 \
  --request-budget 500
```

Lab mode for intentionally vulnerable labs:

```bash
python3 main.py \
  --lab-mode \
  --target http://127.0.0.1:3000 \
  --yes \
  --browser \
  --max-pages 160 \
  --max-depth 4 \
  --max-params 250 \
  --request-budget 700 \
  --asset-doc-limit 40
```

For public intentionally vulnerable demo labs, confirm the lab owner permits automated scans before using it.

## Output

Reports are generated in:

```text
reports/output/cai-superior/<host>/
```

Primary reports:

```text
final-findings-dashboard.md
final-findings-dashboard.txt
final-findings-dashboard.json
autonomous-scan-report.md
autonomous-scan-report.json
parameter-inventory-v2.json
owasp-coverage-report.md
phase-runner-summary.json
cai-react-summary.json
evidence/evidence-index.md
```
