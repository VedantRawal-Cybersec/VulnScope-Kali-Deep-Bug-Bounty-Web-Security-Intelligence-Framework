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

def ask_consent(target: str | None = None) -> tuple[str, bool, bool]:
    print(BANNER)
    if not target:
        target = normalize_target(input('Enter target URL/domain: ').strip())
    print('\nWARNING AND CONSENT')
    print('- Run only on assets you own or have written permission to review.')
    print('- The session is scope locked to the target host and optional subdomains.')
    print('- You are responsible for authorization and lawful use.')
    include_subdomains = input('Include subdomains? yes/no: ').strip().lower() in {'y', 'yes'}
    google_pair = input('Use saved two-account comparison if available? yes/no: ').strip().lower() in {'y', 'yes'}
    confirm = input('Type YES to confirm and start: ').strip()
    if confirm != 'YES':
        raise SystemExit('Consent not confirmed. Exiting.')
    return normalize_target(target), include_subdomains, google_pair
