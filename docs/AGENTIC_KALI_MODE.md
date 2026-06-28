# Agentic Kali Mode

Agentic Kali Mode makes VulnScope work like a guided Kali-style workflow orchestrator.

It is designed to be more useful than a single scanner because it chains:

1. VulnScope scanner
2. AI Discovery Engine
3. Mythic Hunter validation
4. Advanced Uplift Analyzer
5. Report export ZIP

## Safety Boundary

This mode is intentionally safe and authorized-only.

It does not:

- exploit targets
- brute force accounts
- capture credentials
- dump databases
- establish persistence
- bypass authentication
- run unknown external tools automatically

It performs evidence collection, AI-assisted discovery, validation, reportability scoring, and report packaging.

## Run Full Workflow

```bash
python3 agentic_kali_mode.py --url https://example.com --full --yes
```

For slow/CDN-heavy sites:

```bash
python3 agentic_kali_mode.py --url https://www.bmw-motorrad.de --full --max-pages 5 --timeout 45 --delay 1.0 --retries 3 --yes
```

With selected AI providers:

```bash
python3 agentic_kali_mode.py --url https://example.com --full --providers openai,gemini,groq,openrouter --yes
```

Dry run first:

```bash
python3 agentic_kali_mode.py --url https://example.com --full --dry-run
```

## Modular Runs

Scanner + AI discovery only:

```bash
python3 agentic_kali_mode.py --url https://example.com --with-ai --yes
```

Scanner + Mythic validation:

```bash
python3 agentic_kali_mode.py --url https://example.com --with-mythic --yes
```

Scanner + uplift analyzer:

```bash
python3 agentic_kali_mode.py --url https://example.com --with-uplift --yes
```

Scanner + export:

```bash
python3 agentic_kali_mode.py --url https://example.com --export --yes
```

## Output

Main report:

```text
reports/output/target-report.md
reports/output/evidence.json
```

AI discovery:

```text
reports/output/ai-discovery/
```

Mythic Hunter:

```text
reports/output/mythic/
```

Uplift Analyzer:

```text
reports/output/uplift/
```

Export ZIP:

```text
~/Downloads/vulnscope-report-pack-*.zip
```
