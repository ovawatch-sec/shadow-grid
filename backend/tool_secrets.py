"""Runtime API key handling for optional recon and AI tools.

Secrets are persisted through storage, then applied to process environment
variables before tool availability checks and scan execution.
"""
from __future__ import annotations

import os
from typing import Any, Iterable

MASK = "••••••••"

KEY_ENV_MAP: dict[str, str] = {
    # Recon/provider APIs
    "pdcp_api_key": "PDCP_API_KEY",
    "github_token": "GITHUB_TOKEN",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "chaos_key": "CHAOS_KEY",
    # WPScan WordPress Vulnerability Database API token
    "wpscan_api_token": "WPSCAN_API_TOKEN",
    # SerpApi Google Search (for live Google dorking results)
    "serpapi_api_key": "SERPAPI_API_KEY",
    "hunter_api_key": "HUNTER_API_KEY",
    # AI providers
    "openai_api_key": "OPENAI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "google_ai_api_key": "GOOGLE_AI_API_KEY",
    "deepseek_api_key": "DEEPSEEK_API_KEY",
    "groq_api_key": "GROQ_API_KEY",
}

AI_KEY_FIELDS = {
    "openai_api_key",
    "anthropic_api_key",
    "google_ai_api_key",
    "deepseek_api_key",
    "groq_api_key",
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


#: Variables supplied by a local credential file (see ``env_file``). Stored
#: keys never overwrite these, so a CLI run stays bound to the file it loaded.
_locked_env_keys: set[str] = set()


def lock_env_keys(env_names: Iterable[str]) -> None:
    """Protect externally supplied environment values from stored config."""
    known = set(KEY_ENV_MAP.values())
    _locked_env_keys.update(name for name in env_names if name in known)


def locked_env_keys() -> frozenset[str]:
    """Return the variables currently protected from stored-config overwrite."""
    return frozenset(_locked_env_keys)


def clear_locked_env_keys() -> None:
    """Release every protected variable (used by the test suite)."""
    _locked_env_keys.clear()


def apply_tool_api_keys(config: dict[str, Any] | None, *, respect_locks: bool = True) -> None:
    """Export stored keys to the process environment.

    ``respect_locks`` keeps credentials loaded from a local file in place. An
    explicit save from the Settings UI passes ``False`` so the operator's newest
    value always takes effect in the running process.
    """
    for key, env_name in KEY_ENV_MAP.items():
        if respect_locks and env_name in _locked_env_keys:
            continue
        value = str((config or {}).get(key, "") or "").strip()
        if value and value != MASK:
            os.environ[env_name] = value
            if not respect_locks:
                _locked_env_keys.discard(env_name)


def has_any_ai_api_key(config: dict[str, Any] | None = None) -> bool:
    source = normalize_tool_api_keys(config) if config is not None else {
        key: os.environ.get(env, "") for key, env in KEY_ENV_MAP.items()
    }
    return any(str(source.get(key, "") or "").strip() for key in AI_KEY_FIELDS)
