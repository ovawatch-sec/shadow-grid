"""Credential headers must never be broadcast across a discovered host list."""
from __future__ import annotations

from pathlib import Path

import pytest

from models import Scan, ToolCategory
from request_config import (
    headers_for_host,
    host_allows_credentials,
    is_credential_header,
    split_credential_headers,
    validate_credential_hosts,
)
from scan_engine import _tool_extra
from tools.base import BaseTool, RunResult


class _StubTool(BaseTool):
    """Minimal concrete tool used to exercise the header helpers."""

    name = "stub"
    binary_name = None
    category = ToolCategory.HTTP

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        return RunResult("", "", 0, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict]:
        return []


def _tool(tmp_path: Path, hosts: list[str]) -> _StubTool:
    tool = _StubTool(tmp_path, tmp_path)
    tool._request_headers = {"User-Agent": "ShadowGrid/3.1"}
    tool._credential_headers = {"Authorization": "Bearer secret-token"}
    tool._credential_hosts = hosts
    tool._credentials_withheld = False
    return tool


# ── Classification ───────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    "Authorization", "cookie", "X-API-Key", "X-Acme-Session", "x-auth-token", "X-Client-Secret",
])
def test_identity_headers_are_classified_as_credentials(name) -> None:
    assert is_credential_header(name)


@pytest.mark.parametrize("name", ["Accept", "X-Request-Id", "X-Forwarded-For", "Referer"])
def test_ordinary_headers_are_not_credentials(name) -> None:
    assert not is_credential_header(name)


def test_split_separates_identity_from_broadcast_headers() -> None:
    safe, credentials = split_credential_headers({
        "User-Agent": "ShadowGrid/3.1", "X-Trace": "1",
        "Authorization": "Bearer t", "Cookie": "session=abc",
    })
    assert safe == {"User-Agent": "ShadowGrid/3.1", "X-Trace": "1"}
    assert credentials == {"Authorization": "Bearer t", "Cookie": "session=abc"}


# ── Allowlist semantics ──────────────────────────────────────────

def test_empty_allowlist_denies_every_host() -> None:
    assert host_allows_credentials("app.example.com", []) is False


def test_wildcard_covers_subdomains_and_the_apex() -> None:
    allowlist = ["*.example.com"]
    assert host_allows_credentials("app.example.com", allowlist)
    assert host_allows_credentials("deep.app.example.com", allowlist)
    assert host_allows_credentials("example.com", allowlist)
    assert not host_allows_credentials("example.com.attacker.test", allowlist)


def test_direct_ip_never_inherits_a_hostname_allowance() -> None:
    # origin_exposure probes raw IPs; a session must not ride along.
    assert not host_allows_credentials("203.0.113.10", ["*.example.com"])
    assert host_allows_credentials("203.0.113.10", ["203.0.113.10"])


def test_allowlist_accepts_pasted_urls_and_ports() -> None:
    assert validate_credential_hosts(
        ["https://app.example.com:8443/login", "*.staging.example.com", "app.example.com"]
    ) == ["app.example.com", "*.staging.example.com"]


def test_allowlist_rejects_malformed_entries() -> None:
    with pytest.raises(ValueError):
        validate_credential_hosts(["not a host"])


def test_headers_for_host_attaches_only_allowed_credentials() -> None:
    safe = {"User-Agent": "ShadowGrid/3.1"}
    credentials = {"Authorization": "Bearer t"}
    allowed = headers_for_host(safe, credentials, "app.example.com", ["app.example.com"])
    denied = headers_for_host(safe, credentials, "takeover.example.com", ["app.example.com"])
    assert allowed["Authorization"] == "Bearer t"
    assert "Authorization" not in denied


# ── Tool-level enforcement ───────────────────────────────────────

def test_list_driven_tool_sends_credentials_only_when_every_host_is_allowed(tmp_path) -> None:
    tool = _tool(tmp_path, ["app.example.com"])
    args = tool._header_args(hosts=["app.example.com"])
    assert "Authorization: Bearer secret-token" in args

    tool = _tool(tmp_path, ["app.example.com"])
    mixed = tool._header_args(hosts=["app.example.com", "forgotten.example.com"])
    assert not any("Authorization" in value for value in mixed)
    assert tool._credential_note()


def test_tool_that_cannot_name_its_targets_gets_no_credentials(tmp_path) -> None:
    tool = _tool(tmp_path, ["app.example.com"])
    args = tool._header_args()
    assert not any("Authorization" in value for value in args)
    assert "withheld" in tool._credential_note()


def test_no_notice_when_nothing_was_withheld(tmp_path) -> None:
    tool = _tool(tmp_path, ["app.example.com"])
    tool._header_args(hosts=["app.example.com"])
    assert tool._credential_note() == ""


def test_hosts_in_extracts_hostnames_from_urls(tmp_path) -> None:
    tool = _tool(tmp_path, [])
    assert tool._hosts_in([
        "https://app.example.com/login", "https://app.example.com:8443/x",
        "http://other.example.com", "garbage",
    ]) == ["app.example.com", "other.example.com", "garbage"]


def test_engine_extras_keep_credentials_separate() -> None:
    scan = Scan(
        project_id="p1", tools=["httpx"],
        custom_headers={"Authorization": "Bearer t", "X-Trace": "1"},
        credential_hosts=["app.example.com"],
    )
    extra = _tool_extra(scan)
    assert extra["credential_headers"] == {"Authorization": "Bearer t"}
    assert "Authorization" not in extra["request_headers"]
    assert extra["request_headers"]["X-Trace"] == "1"
    assert extra["credential_hosts"] == ["app.example.com"]
