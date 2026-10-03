"""Local credential file loading for CLI and non-container runs."""
from __future__ import annotations

import os

import pytest

import env_file
import tool_secrets
from env_file import (
    ENV_FILE_VAR,
    apply_values,
    candidate_paths,
    discover_env_file,
    load_env_file,
    parse_env_text,
)


@pytest.fixture(autouse=True)
def _clean_locks():
    tool_secrets.clear_locked_env_keys()
    yield
    tool_secrets.clear_locked_env_keys()


# ── Parsing ──────────────────────────────────────────────────────

def test_parses_plain_quoted_and_exported_entries() -> None:
    values = parse_env_text(
        "﻿# ShadowGrid credentials\n"
        "SHODAN_API_KEY=plain-value\n"
        "export HUNTER_API_KEY=exported-value\n"
        "  WPSCAN_API_TOKEN = spaced-value  \n"
        "SERPAPI_API_KEY='single #quoted'\n"
        'OPENAI_API_KEY="double\\tquoted"\n'
        "\n"
    )

    assert values == {
        "SHODAN_API_KEY": "plain-value",
        "HUNTER_API_KEY": "exported-value",
        "WPSCAN_API_TOKEN": "spaced-value",
        "SERPAPI_API_KEY": "single #quoted",
        "OPENAI_API_KEY": "double\tquoted",
    }


def test_strips_inline_comments_only_outside_quotes() -> None:
    values = parse_env_text(
        "SHODAN_API_KEY=value   # trailing note\n"
        "HUNTER_API_KEY=keeps#hash\n"
        'GROQ_API_KEY="  padded # value  "\n'
    )

    assert values["SHODAN_API_KEY"] == "value"
    assert values["HUNTER_API_KEY"] == "keeps#hash"
    assert values["GROQ_API_KEY"] == "  padded # value  "


def test_skips_malformed_lines_without_failing() -> None:
    values = parse_env_text(
        "NOT_AN_ASSIGNMENT\n"
        "9INVALID=value\n"
        "has space=value\n"
        "SHODAN_API_KEY=survivor\n"
    )

    assert values == {"SHODAN_API_KEY": "survivor"}


# ── Applying to the environment ──────────────────────────────────

def test_shell_environment_wins_over_the_file(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "from-shell")

    result = apply_values({"SHODAN_API_KEY": "from-file"})

    assert os.environ["SHODAN_API_KEY"] == "from-shell"
    assert result.overridden == ["SHODAN_API_KEY"]
    assert result.applied == []


def test_override_flag_lets_the_file_win(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "from-shell")

    apply_values({"SHODAN_API_KEY": "from-file"}, override=True)

    assert os.environ["SHODAN_API_KEY"] == "from-file"


def test_exported_but_empty_variable_counts_as_unset(monkeypatch) -> None:
    # docker-compose writes PDCP_API_KEY= when the host variable is absent.
    monkeypatch.setenv("PDCP_API_KEY", "")

    apply_values({"PDCP_API_KEY": "from-file"})

    assert os.environ["PDCP_API_KEY"] == "from-file"


def test_blank_placeholders_are_ignored(monkeypatch) -> None:
    monkeypatch.delenv("CHAOS_KEY", raising=False)

    result = apply_values({"CHAOS_KEY": "   "})

    assert "CHAOS_KEY" not in os.environ
    assert result.blank == ["CHAOS_KEY"]


# ── Discovery ────────────────────────────────────────────────────

def test_discovery_prefers_the_working_directory(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    local = tmp_path / ".env"
    local.write_text("SHODAN_API_KEY=local\n", encoding="utf-8")

    assert discover_env_file(search_from=tmp_path) == local


def test_discovery_honours_the_environment_pointer(monkeypatch, tmp_path) -> None:
    pointed = tmp_path / "custom.env"
    pointed.write_text("SHODAN_API_KEY=pointed\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SHODAN_API_KEY=local\n", encoding="utf-8")
    monkeypatch.setenv(ENV_FILE_VAR, str(pointed))

    assert discover_env_file(search_from=tmp_path) == pointed


def test_missing_explicit_file_is_an_error(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)

    with pytest.raises(FileNotFoundError, match="--env-file"):
        discover_env_file(tmp_path / "absent.env")


def test_no_candidate_file_returns_none(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    monkeypatch.setattr(env_file, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(env_file, "_user_config_path", lambda: tmp_path / "home" / ".env")

    assert discover_env_file(search_from=tmp_path) is None


def test_candidate_paths_are_unique_and_ordered(tmp_path) -> None:
    paths = candidate_paths(tmp_path)

    assert paths[0] == tmp_path / ".env"
    assert len(paths) == len(set(paths))


# ── Precedence against keys stored in the database ───────────────

def test_file_credentials_survive_stored_keys(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("HUNTER_API_KEY", raising=False)
    (tmp_path / ".env").write_text("SHODAN_API_KEY=from-file\n", encoding="utf-8")

    result = load_env_file(search_from=tmp_path)
    assert result.applied == ["SHODAN_API_KEY"]
    assert tool_secrets.locked_env_keys() == {"SHODAN_API_KEY"}

    # A scan loads whatever the Settings UI saved; the local file still wins,
    # and unrelated stored keys are still applied.
    tool_secrets.apply_tool_api_keys({
        "shodan_api_key": "from-database", "hunter_api_key": "from-database",
    })

    assert os.environ["SHODAN_API_KEY"] == "from-file"
    assert os.environ["HUNTER_API_KEY"] == "from-database"


def test_explicit_settings_save_outranks_the_file(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "from-file")
    tool_secrets.lock_env_keys(["SHODAN_API_KEY"])

    tool_secrets.apply_tool_api_keys({"shodan_api_key": "from-ui"}, respect_locks=False)

    assert os.environ["SHODAN_API_KEY"] == "from-ui"
    assert tool_secrets.locked_env_keys() == frozenset()


def test_only_known_credentials_are_locked(monkeypatch) -> None:
    tool_secrets.lock_env_keys(["SHODAN_API_KEY", "PATH", "RANDOM_SETTING"])

    assert tool_secrets.locked_env_keys() == {"SHODAN_API_KEY"}


def test_loading_nothing_reports_no_file(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    monkeypatch.setattr(env_file, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(env_file, "_user_config_path", lambda: tmp_path / "home" / ".env")

    result = load_env_file(search_from=tmp_path)

    assert not result.loaded
    assert result.applied == []
