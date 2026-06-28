from __future__ import annotations

LAB_TARGETS = {
    "juice-shop-local": {
        "url": "http://127.0.0.1:3000",
        "type": "local_lab",
        "notes": "OWASP Juice Shop running locally. Start it yourself before running benchmark.",
    },
    "dvwa-local": {
        "url": "http://127.0.0.1:8080",
        "type": "local_lab",
        "notes": "DVWA running locally. Use only your own lab instance.",
    },
    "webgoat-local": {
        "url": "http://127.0.0.1:8080/WebGoat",
        "type": "local_lab",
        "notes": "WebGoat running locally. Use only your own lab instance.",
    },
    "portswigger-manual": {
        "url": "manual",
        "type": "training_lab",
        "notes": "Use exported HAR or owned lab URL from PortSwigger Academy. Do not automate against accounts you do not control.",
    },
}


def list_labs() -> dict:
    return LAB_TARGETS


def get_lab(name: str) -> dict | None:
    return LAB_TARGETS.get(name)
