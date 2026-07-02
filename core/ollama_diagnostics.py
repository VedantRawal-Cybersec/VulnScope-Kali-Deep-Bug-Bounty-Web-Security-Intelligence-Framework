#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class OllamaStatus:
    reachable: bool = False
    model: str = ""
    label: str = "Not checked"
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def run_ollama_diagnostics(*args, **kwargs) -> OllamaStatus:
    return OllamaStatus(label="Diagnostics placeholder")
