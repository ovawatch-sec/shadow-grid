"""env_file.py — local credential file support for non-container runs.

The container receives API keys either from the Settings UI (persisted in
SQLite) or from Docker environment variables. Neither path exists for a bare
``python3 recon.py`` run, so the CLI reads the same credentials from a local
``.env`` file. ``.env.example`` at the repository root documents every
supported variable.

Precedence rules, in order:

1. A non-empty value already exported in the process environment wins, so
   ``SHODAN_API_KEY=... python3 recon.py -d example.com`` overrides the file
   for a single run.
2. Values from the ``.env`` file.
3. Keys saved in the database through the Settings UI — those are applied by
   :func:`tool_secrets.apply_tool_api_keys`, which skips variables this module
   has loaded (see :func:`tool_secrets.lock_env_keys`).

Blank entries are ignored, so a freshly copied ``.env.example`` never shadows
a real environment variable. Multi-line values are not supported.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Iterable, NamedTuple

logger = logging.getLogger(__name__)

#: Environment variable that points at an explicit credential file.
ENV_FILE_VAR = "SHADOWGRID_ENV_FILE"
DEFAULT_FILENAME = ".env"
REPO_ROOT = Path(__file__).resolve().parents[1]

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'"}


class EnvFileResult(NamedTuple):
    """Outcome of a credential file load."""

    path: Path | None
    applied: list[str]      # variables taken from the file
    overridden: list[str]   # variables the process environment already supplied
    blank: list[str]        # placeholder entries with no value

    @property
    def loaded(self) -> bool:
        return self.path is not None


def _unescape(value: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _strip_inline_comment(value: str) -> str:
    """Drop a trailing ``# comment`` from an unquoted value."""
    for index, char in enumerate(value):
        if char == "#" and (index == 0 or value[index - 1] in " \t"):
            return value[:index]
    return value


def parse_env_text(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines into a mapping, skipping anything malformed."""
    values: dict[str, str] = {}
    for number, raw in enumerate(text.lstrip("﻿").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export"):].lstrip()
        if "=" not in line:
            logger.warning("Ignored malformed credential line %d: no '=' separator", number)
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            logger.warning("Ignored credential line %d: %r is not a valid variable name", number, key)
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            quote, value = value[0], value[1:-1]
            value = _unescape(value) if quote == '"' else value
        else:
            value = _strip_inline_comment(value).strip()
        values[key] = value
    return values


def parse_env_file(path: str | Path) -> dict[str, str]:
    """Parse a credential file from disk."""
    return parse_env_text(Path(path).read_text(encoding="utf-8"))


def _user_config_path() -> Path | None:
    try:
        return Path.home() / ".config" / "shadowgrid" / DEFAULT_FILENAME
    except RuntimeError:  # no resolvable home directory
        return None


def candidate_paths(search_from: str | Path | None = None) -> list[Path]:
    """Return the default search order used when no file is given explicitly."""
    start = Path(search_from) if search_from is not None else Path.cwd()
    candidates = [start / DEFAULT_FILENAME, REPO_ROOT / DEFAULT_FILENAME]
    user_config = _user_config_path()
    if user_config is not None:
        candidates.append(user_config)
    seen: set[Path] = set()
    ordered: list[Path] = []
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved not in seen:
            seen.add(resolved)
            ordered.append(resolved)
    return ordered


def discover_env_file(
    explicit: str | Path | None = None, search_from: str | Path | None = None,
) -> Path | None:
    """Locate the credential file to load.

    An explicitly requested file (CLI flag or ``SHADOWGRID_ENV_FILE``) must
    exist — a typo in a path is an error, not a silent fallback to defaults.
    """
    requested = explicit if explicit is not None else os.environ.get(ENV_FILE_VAR) or None
    if requested:
        path = Path(requested).expanduser()
        if not path.is_file():
            source = "--env-file" if explicit is not None else ENV_FILE_VAR
            raise FileNotFoundError(f"{source} points at a missing credential file: {path}")
        return path
    for candidate in candidate_paths(search_from):
        if candidate.is_file():
            return candidate
    return None


def apply_values(values: dict[str, str], *, override: bool = False) -> EnvFileResult:
    """Apply parsed values to ``os.environ`` and report what happened."""
    applied: list[str] = []
    overridden: list[str] = []
    blank: list[str] = []
    for key, value in values.items():
        if not value.strip():
            blank.append(key)
            continue
        # An exported-but-empty variable (docker-compose writes these) counts
        # as unset so the file can still supply the credential.
        if not override and os.environ.get(key, "").strip():
            overridden.append(key)
            continue
        os.environ[key] = value
        applied.append(key)
    return EnvFileResult(None, applied, overridden, blank)


def load_env_file(
    explicit: str | Path | None = None,
    *,
    override: bool = False,
    search_from: str | Path | None = None,
    lock: bool = True,
) -> EnvFileResult:
    """Discover, parse, and apply a credential file.

    When ``lock`` is set, applied tool credentials are protected from being
    overwritten by keys stored in the database, so the local file stays
    authoritative for the run.
    """
    path = discover_env_file(explicit, search_from)
    if path is None:
        return EnvFileResult(None, [], [], [])
    try:
        values = parse_env_file(path)
    except OSError as exc:
        raise OSError(f"Could not read credential file {path}: {exc}") from exc
    result = apply_values(values, override=override)._replace(path=path)
    if lock and result.applied:
        from tool_secrets import lock_env_keys
        lock_env_keys(result.applied)
    logger.info(
        "Loaded %d credential(s) from %s (%d already set in the environment)",
        len(result.applied), path, len(result.overridden),
    )
    return result


def describe(names: Iterable[str]) -> str:
    """Render variable names for terminal output without printing values."""
    ordered = sorted(names)
    return ", ".join(ordered) if ordered else "(none)"
