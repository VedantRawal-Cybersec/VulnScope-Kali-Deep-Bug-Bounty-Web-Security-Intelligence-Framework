# Auto Arsenal Mode

Auto Arsenal Mode turns VulnScope-Kali into a curated AI-assisted Kali workflow platform.

It does not blindly download random GitHub repositories. It uses a maintained catalog of known tools, safe templates, approval gates, and user-local installation where possible.

## New Files

```text
auto_mode.py
arsenal/
├── __init__.py
├── tool_catalog.yaml
├── catalog.py
├── installer.py
├── healthcheck.py
└── runner.py
automation/n8n_daily_module_factory_blueprint.json
```

## List Profiles

```bash
python3 auto_mode.py --list-profiles
```

Profiles:

```text
passive-intel
bug-bounty-safe
api-heavy
js-heavy
deep-validation
```

## Healthcheck

```bash
python3 auto_mode.py --healthcheck --profile bug-bounty-safe
```

## Full Auto Mode

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --full
```

With AI providers:

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --full --providers openai,gemini,groq,openrouter
```

For slow/CDN-heavy sites:

```bash
python3 auto_mode.py --url https://www.bmw-motorrad.de --profile bug-bounty-safe --full --max-pages 5 --timeout 45 --delay 1.0 --retries 3
```

## Auto Install Only

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --auto-install
```

## Use Installed Profile Tools

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --with-tools
```

## Dry Run

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --full --dry-run
```

## Output

```text
reports/output/auto-mode-summary.json
reports/output/arsenal/healthcheck.json
reports/output/arsenal/*.txt
reports/output/target-report.md
reports/output/evidence.json
reports/output/ai-discovery/
reports/output/mythic/
reports/output/uplift/
```

## n8n Daily Module Factory

Blueprint file:

```text
automation/n8n_daily_module_factory_blueprint.json
```

Recommended model:

```text
n8n daily schedule
→ GitHub issue/roadmap scan
→ AI creates safe improvement plan
→ path guard validates allowed files
→ create branch
→ commit module/docs/tests
→ open pull request
→ notify owner
→ manual merge only
```

Do not allow n8n or AI to push directly to main.
