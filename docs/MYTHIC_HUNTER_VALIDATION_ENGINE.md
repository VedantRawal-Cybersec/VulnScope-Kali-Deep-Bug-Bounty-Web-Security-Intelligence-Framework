# Mythic Hunter Validation Engine

Mythic Hunter is an evidence-first validation layer for VulnScope-Kali.

It does not replace the existing scanner. It analyzes scanner output, endpoint lists, JavaScript snippets, headers, API responses, Burp-style text, markdown, JSON, and HAR-like text to decide what is real, what is weak, and what still needs manual proof.

Core rule:

```text
No evidence = no confirmed vulnerability.
```

## Status Labels

Every issue is classified as one of:

- DISCOVERED
- HYPOTHESIS
- NEEDS_MANUAL_VALIDATION
- FALSE_POSITIVE_LIKELY
- CONFIRMED_OBSERVATION
- CONFIRMED_VULNERABILITY
- NOT_REPORTABLE

## Implemented Features

- Scanner finding importer
- Endpoint and parameter extraction
- Workflow mapper
- Trust-boundary analyzer
- JavaScript intelligence
- Secret-like signal classifier
- State and redirect parameter analyzer
- IDOR / BOLA validation assistant logic
- Auth vs unauth comparison logic
- Source map analyzer
- Feature flag / debug analyzer
- Header, cookie, cache, and CORS auditor
- Business-logic planner
- Bug-chain builder
- OpenMythos-inspired reasoning loop
- Expert router through specialist classification logic
- Stability guard
- Reportability scorer
- Evidence-vault data model
- Coda report builder
- Portfolio proof export
- Acceptance tests

## Run

```bash
python3 mythic_hunter_cli.py --input scanner-output.txt
```

Analyze short text:

```bash
python3 mythic_hunter_cli.py --text 'Missing Content-Security-Policy'
```

Deep mode:

```bash
python3 mythic_hunter_cli.py --input scanner-output.txt --depth DEEP_HUNTER_MODE
```

Paranoid false-positive review:

```bash
python3 mythic_hunter_cli.py --input scanner-output.txt --depth PARANOID_FALSE_POSITIVE_REVIEW
```

Run acceptance tests:

```bash
python3 mythic_hunter_cli.py --run-tests
```

## Output

```text
reports/output/mythic/
├── mythic-report.md
├── mythic-evidence.json
├── mythic-proof-exports.md
└── mythic-acceptance-tests.json
```

## Safety

Mythic Hunter does not make network requests. It does not brute force, bypass authentication, use tokens, or access private data. It only analyzes evidence supplied by the user and produces safe validation workflows.
