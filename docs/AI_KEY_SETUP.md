# AI API Key Setup

VulnScope-Kali now includes an interactive API key setup flow.

## Add keys locally

Run:

```bash
python3 vulnscope.py --setup-ai-keys
```

The tool will ask for:

- OpenAI API key
- Google Gemini API key
- Groq API key
- OpenRouter API key

Leave any provider blank to skip it.

Keys are saved only to a local ignored file:

```text
.env.local
```

The file is ignored by git and should never be uploaded or committed.

## Check key status

Run:

```bash
python3 vulnscope.py --ai-key-status
```

The tool shows whether each key is configured, but it never prints the actual values.

## Run AI review

```bash
python3 vulnscope.py --url https://example.com --mode passive --max-pages 10 --ai-review
```

Use selected providers:

```bash
python3 vulnscope.py --url https://example.com --mode passive --ai-review --ai-providers openai,groq
```

## Safety

- Do not paste real keys into GitHub.
- Do not share keys in screenshots.
- Regenerate keys if they were exposed anywhere public or semi-public.
- Treat AI output as advisory only.
