from rich.console import Console
from rich.panel import Panel

console = Console()


def print_banner(version: str) -> None:
    banner = r'''
 __     __     _       ____                      
 \ \   / /   _| |_ __ / ___|  ___ ___  _ __   ___
  \ \ / / | | | | '_ \\___ \ / __/ _ \| '_ \ / _ \
   \ V /| |_| | | | | |___) | (_| (_) | |_) |  __/
    \_/  \__,_|_|_| |_|____/ \___\___/| .__/ \___|
                                       |_|        
'''
    body = f"""{banner}
VulnScope-Kali
Deep Bug Bounty Web Security Intelligence Framework

Authorized Testing | Deep Discovery | Correlation | Reports

Version      : {version}
Environment  : Kali Linux / Python 3
Engine       : Safe Passive Intelligence - Phase 1
Output       : Markdown / JSON
"""
    console.print(Panel(body, title="VulnScope-Kali", border_style="cyan"))
