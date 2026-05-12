"""Runtime API key handling for optional recon tools.

Secrets are persisted through storage, then applied to process environment
variables before tool availability checks and scan execution.
"""
from __future__ import annotations

import os
from typing import Any

MASK = "••••••••"

KEY_ENV_MAP: dict[str, str] = {
    "pdcp_api_key": "PDCP_API_KEY",
    "github_token": "GITHUB_TOKEN",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "chaos_key": "CHAOS_KEY",
}

DEFAULT_TOOL_API_KEYS: dict[str, str] = {key: "" for key in KEY_ENV_MAP}


def normalize_tool_api_keys(config: dict[str, Any] | None) -> dict[str, str]:
    clean = DEFAULT_TOOL_API_KEYS.copy()
    for key in clean:
        value = "" if not config else str(config.get(key, "") or "")
        if value == MASK:
            value = ""
        clean[key] = value.strip()
    return clean


def merge_tool_api_keys(existing: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, str]:
    """Merge a UI payload without wiping saved secrets when password fields are blank.

    - Blank/masked incoming values keep the existing value.
    - A value of ``__clear__`` intentionally removes the stored key.
    """
    current = normalize_tool_api_keys(existing)
    incoming = incoming or {}
    for key in KEY_ENV_MAP:
        if key not in incoming:
            continue
        value = str(incoming.get(key) or "").strip()
        if not value or value == MASK:
            continue
        if value == "__clear__":
            current[key] = ""
        else:
            current[key] = value
    return current


def mask_tool_api_keys(config: dict[str, Any] | None) -> dict[str, str]:
    clean = normalize_tool_api_keys(config)
    return {key: (MASK if value else "") for key, value in clean.items()}


def apply_tool_api_keys(config: dict[str, Any] | None) -> None:
    for key, env_name in KEY_ENV_MAP.items():
        value = str((config or {}).get(key, "") or "").strip()
        if value and value != MASK:
            os.environ[env_name] = value
