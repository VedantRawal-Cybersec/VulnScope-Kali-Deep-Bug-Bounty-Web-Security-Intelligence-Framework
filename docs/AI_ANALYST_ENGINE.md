# AI Analyst Engine

VulnScope-Kali supports an optional AI Analyst Engine for advisory finding review.

The engine is disabled by default. Enable it only when you want redacted scan evidence to be reviewed by configured AI providers.

## Providers

Supported providers:

- OpenAI
- Google Gemini
- Groq
- OpenRouter

## Secret Handling

Do not commit real API credentials to GitHub.

Use local environment variables, a local shell profile, or a secrets manager. The repository includes `config/ai_providers.example.env` as a template only.

## Run With AI Review

```bash
python3 vulnscope.py --url https://example.com --mode passive --max-pages 10 --ai-review
```

Run with selected providers:

```bash
python3 vulnscope.py --url https://example.com --mode passive --ai-review --ai-providers openai,groq
```

## What AI Review Does

- Finding prioritization
- False-positive risk review
- Missing evidence detection
- Report-readiness guidance
- Safe next-step recommendations

## What AI Review Must Not Do

- It must not generate exploit chains.
- It must not brute force accounts.
- It must not capture credentials.
- It must not dump databases.
- It must not ignore scope.
- It must not auto-enable risky modules.

## Output

AI review output is stored inside `reports/output/evidence.json` under `metadata.ai_review`.

The review is advisory only and must not replace manual validation.
