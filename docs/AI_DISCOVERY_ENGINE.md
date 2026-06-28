# AI Discovery Engine

The AI Discovery Engine is different from AI Review.

- AI Review checks existing findings and improves triage.
- AI Discovery scans the redacted evidence and proposes additional potential findings the rule-based modules may have missed.

It does not make network requests. It does not exploit anything. It does not mark findings as confirmed vulnerabilities unless explicit proof exists in the evidence.

## Run After a VulnScope Scan

```bash
python3 vulnscope.py --url https://example.com --mode passive --max-pages 10
python3 ai_discovery_cli.py --input reports/output/evidence.json
```

## Run With Specific Providers

```bash
python3 ai_discovery_cli.py --input reports/output/evidence.json --providers openai,groq
```

All providers:

```bash
python3 ai_discovery_cli.py --input reports/output/evidence.json --providers openai,gemini,groq,openrouter
```

## Output

```text
reports/output/ai-discovery/
├── ai-discovery-results.json
└── ai-discovery-report.md
```

## What It Looks For

The AI Discovery Engine asks models to inspect:

- endpoints
- parameters
- API routes
- route names
- access-control candidates
- state/redirect candidates
- source map indicators
- secret-like exposure signals
- CORS/cache/cookie/header posture
- workflow and business logic hints
- missing evidence and false-positive risks

## Safety Rules

- No exploit payload generation
- No brute force
- No bypass steps
- No credential capture
- No database dumping
- No destructive actions
- No confirmed vulnerability without proof
- Findings remain manual-review candidates unless evidence proves otherwise
