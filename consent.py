from __future__ import annotations

from urllib.parse import urlparse

BANNER = r'''
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
                 VULNSCOPE NEURAL AUTONOMOUS REVIEW AGENT
'''


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError('Target is empty')
    return raw if '://' in raw else 'https://' + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    if not parsed.hostname:
        raise ValueError('Invalid target')
    return parsed.hostname.lower()


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = '[Y/n]' if default else '[y/N]'
    raw = input(prompt + ' ' + suffix + ': ').strip().lower()
    if not raw:
        return default
    return raw in {'y', 'yes'}


def ask_choice(prompt: str, choices: list[str], default: str) -> str:
    choices_lower = [c.lower() for c in choices]
    while True:
        raw = input(prompt + ' (' + '/'.join(choices) + ') [' + default + ']: ').strip().lower()
        value = raw or default
        if value in choices_lower:
            return value
        print('Invalid choice. Allowed values: ' + ', '.join(choices))


def collect_session_details(existing_target: str | None = None) -> dict:
    print(BANNER)
    print('Step 1 - Target')
    target = normalize_target(existing_target or input('Enter target URL/domain: ').strip())
    host = host_from_target(target)
    print('\nStep 2 - Warning and consent')
    print('- This tool is for authorized security review only.')
    print('- You must own the target or have explicit written permission.')
    print('- Unauthorized use is illegal and you assume all responsibility.')
    print('- The agent will use safe, non-destructive review modules and will respect scope controls.')
    confirm = input('Type YES to confirm authorization for ' + target + ': ').strip()
    if confirm != 'YES':
        raise SystemExit('Consent not confirmed. Exiting.')
    print('\nStep 3 - Agent options')
    include_subdomains = ask_yes_no('Include subdomains in scope?', False)
    model_provider = ask_choice('LLM provider', ['none', 'ollama', 'openai'], 'none')
    model_name = 'llama3'
    if model_provider == 'ollama':
        model_name = input('Ollama model name [llama3]: ').strip() or 'llama3'
    elif model_provider == 'openai':
        model_name = input('OpenAI model name [gpt-4.1-mini]: ').strip() or 'gpt-4.1-mini'
    two_accounts = ask_yes_no('Do you have saved two-account sessions for comparison?', False)
    monitoring = ask_choice('Monitoring frequency', ['none', 'daily', 'weekly'], 'none')
    return {
        'target': target,
        'host': host,
        'include_subdomains': include_subdomains,
        'model_provider': model_provider,
        'model_name': model_name,
        'two_accounts': two_accounts,
        'monitoring_frequency': monitoring,
        'confirmed': True,
    }
