"""Safe assessment-level HTTP identity, header, and credential handling."""
from __future__ import annotations

import re
from typing import Mapping, Sequence
from urllib.parse import urlsplit

DEFAULT_USER_AGENT = "ShadowGrid/3.1"
MAX_CUSTOM_HEADERS = 20
MAX_HEADER_VALUE_LENGTH = 2048
MAX_CREDENTIAL_HOSTS = 50
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
CREDENTIAL_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
BLOCKED_HEADERS = {
    "connection", "content-length", "expect", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "user-agent",
}

#: Headers that carry a session or API identity. These are never broadcast to
#: every discovered host: a scan that enumerates 200 subdomains must not hand a
#: live session token to each of them, including a subdomain that
#: ``subdomain_takeover`` has just flagged as claimable by someone else.
CREDENTIAL_HEADERS = {
    "authorization", "cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-access-token", "x-session-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
}

#: Substrings that mark a custom header as credential-bearing. Deployments
#: invent their own names (``X-Acme-Session``), so classification is by
#: meaning, not by an exhaustive list.
CREDENTIAL_HEADER_HINTS = ("auth", "token", "session", "cookie", "secret", "credential", "apikey", "api-key")


def validate_user_agent(value: str) -> str:
    """Validate and normalize an assessment User-Agent value."""
    normalized = str(value or DEFAULT_USER_AGENT).strip()
    if not normalized or len(normalized) > 512 or "\r" in normalized or "\n" in normalized:
        raise ValueError("User-Agent must be 1-512 characters without line breaks")
    return normalized


def validate_custom_headers(value: Mapping[str, str] | None) -> dict[str, str]:
    """Validate custom end-to-end request headers and reject request smuggling primitives."""
    if not value:
        return {}
    if len(value) > MAX_CUSTOM_HEADERS:
        raise ValueError(f"At most {MAX_CUSTOM_HEADERS} custom headers are allowed")
    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        header_value = str(raw_value).strip()
        lowered = name.lower()
        if not HEADER_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid HTTP header name: {name!r}")
        if lowered in BLOCKED_HEADERS:
            raise ValueError(f"Header {name!r} is managed by ShadowGrid and cannot be overridden")
        if lowered in seen:
            raise ValueError(f"Duplicate HTTP header: {name!r}")
        if not header_value or len(header_value) > MAX_HEADER_VALUE_LENGTH:
            raise ValueError(f"Header {name!r} must contain 1-{MAX_HEADER_VALUE_LENGTH} characters")
        if "\r" in header_value or "\n" in header_value or "\x00" in header_value:
            raise ValueError(f"Header {name!r} contains prohibited control characters")
        seen.add(lowered)
        normalized[name] = header_value
    return normalized


def target_request_headers(user_agent: str, custom_headers: Mapping[str, str]) -> dict[str, str]:
    """Build the headers sent only to assessment targets."""
    return {"User-Agent": validate_user_agent(user_agent), **validate_custom_headers(custom_headers)}


def is_credential_header(name: str) -> bool:
    """Return True when a header carries a session or API identity."""
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    if lowered in CREDENTIAL_HEADERS:
        return True
    return any(hint in lowered for hint in CREDENTIAL_HEADER_HINTS)


def split_credential_headers(
    headers: Mapping[str, str] | None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Separate broadcast-safe headers from credential-bearing ones."""
    safe: dict[str, str] = {}
    credentials: dict[str, str] = {}
    for name, value in (headers or {}).items():
        (credentials if is_credential_header(name) else safe)[name] = value
    return safe, credentials


def validate_credential_hosts(value: Sequence[str] | None) -> list[str]:
    """Validate the host allowlist that credential headers may be sent to.

    Entries are hostnames or single-level ``*.example.com`` wildcards. A URL is
    accepted and reduced to its hostname so operators can paste a target
    straight from the browser.
    """
    if not value:
        return []
    if isinstance(value, (str, bytes)):
        raise ValueError("credential_hosts must be a list of hostnames")
    if len(value) > MAX_CREDENTIAL_HOSTS:
        raise ValueError(f"At most {MAX_CREDENTIAL_HOSTS} credential hosts are allowed")
    normalized: list[str] = []
    for entry in value:
        candidate = str(entry or "").strip().lower()
        if not candidate:
            continue
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        candidate = candidate.split("/", 1)[0]
        if candidate.count(":") == 1 and not candidate.endswith(":"):
            candidate = candidate.rsplit(":", 1)[0]
        candidate = candidate.strip(".")
        if not candidate or not CREDENTIAL_HOST_RE.fullmatch(candidate):
            raise ValueError(f"Invalid credential host: {entry!r}")
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def host_allows_credentials(host: str | None, allowlist: Sequence[str] | None) -> bool:
    """Return True when credential headers may be sent to ``host``.

    An empty allowlist denies every host: credentials are opt-in per target,
    never implied by scope membership. A raw IP literal is only ever matched
    exactly, so direct-origin probing cannot inherit a hostname's session.
    """
    if not allowlist:
        return False
    candidate = str(host or "").strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.split("/", 1)[0]
    if candidate.count(":") == 1 and not candidate.endswith(":"):
        candidate = candidate.rsplit(":", 1)[0]
    candidate = candidate.strip("[]").strip(".")
    if not candidate:
        return False
    for pattern in allowlist:
        rule = str(pattern or "").strip().lower().strip(".")
        if not rule:
            continue
        if rule.startswith("*."):
            suffix = rule[2:]
            if candidate == suffix or candidate.endswith(f".{suffix}"):
                return True
        elif candidate == rule:
            return True
    return False


def headers_for_host(
    safe: Mapping[str, str], credentials: Mapping[str, str],
    host: str | None, allowlist: Sequence[str] | None,
) -> dict[str, str]:
    """Build the header set for one target host, attaching credentials only when allowed."""
    merged = dict(safe)
    if credentials and host_allows_credentials(host, allowlist):
        merged.update(credentials)
    return merged
