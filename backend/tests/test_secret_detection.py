"""Secret detection depth: patterns, entropy, placeholders, and budgeting."""
from __future__ import annotations

import re

from tools.vuln.secret_exposure import (
    MAX_SCRIPT_URLS,
    PATTERNS,
    SecretExposureTool,
    high_entropy_candidates,
    is_placeholder,
    shannon_entropy,
)


def _token(*parts: str) -> str:
    """Assemble a fabricated credential sample from fragments.

    These samples are fake but deliberately shaped like the real thing — that
    is what makes them useful here, and also what makes a secret scanner (and
    GitHub push protection) reject the file if they appear as literals.
    Building them at runtime keeps the detection logic under test without
    committing anything key-shaped.
    """
    return "".join(parts)


STRIPE_KEY = _token("sk_", "live_", "51H8xKjLmNoPqRsTuVwXyZ012")
GOOGLE_KEY = _token("AIza", "SyB1234567890abcdefghijklmnopqrstuv")
SLACK_TOKEN = _token("xoxb", "-1234567890-abcdefghijkl")
GITLAB_TOKEN = _token("glpat", "-ABCDEFGHIJKLMNOPQRST")
NPM_TOKEN = _token("npm_", "a" * 36)
ANTHROPIC_KEY = _token("sk-", "ant-", "abcdefghijklmnopqrstuvwxyz")


def _match(text: str) -> list[str]:
    hits = []
    for name, pattern, _severity in PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append(name)
    return hits


def test_provider_tokens_are_detected() -> None:
    assert "Stripe secret key" in _match(f'key = "{STRIPE_KEY}"')
    assert "Google API key" in _match(f'"{GOOGLE_KEY}"')
    assert "Slack token" in _match(SLACK_TOKEN)
    assert "GitLab token" in _match(GITLAB_TOKEN)
    assert "npm access token" in _match(NPM_TOKEN)
    assert "Anthropic API key" in _match(ANTHROPIC_KEY)


def test_connection_strings_and_headers_are_detected() -> None:
    assert "Database connection string" in _match("postgres://app:s3cretPass@db.internal:5432/main")
    assert "Basic authorization header" in _match('Authorization: "Basic dXNlcjpwYXNzd29yZDEyMw=="')
    assert "Private key material" in _match("-----BEGIN OPENSSH PRIVATE KEY-----")


def test_clean_content_produces_no_hits() -> None:
    assert _match("<html><body>Welcome to our marketing site.</body></html>") == []


# ── Entropy and placeholders ─────────────────────────────────────

def test_entropy_separates_random_values_from_prose() -> None:
    assert shannon_entropy("a9Kd82Ls0qZxWm41PpRt73Vb") > 4.0
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa") < 1.0


def test_documentation_placeholders_are_ignored() -> None:
    for value in ("YOUR_API_KEY", "xxxxxxxxxxxx", "<your-token>", "${API_TOKEN}",
                  "changeme", "placeholder", "null", "short"):
        assert is_placeholder(value), value
    assert not is_placeholder("a9Kd82Ls0qZxWm41PpRt73Vb")


def test_high_entropy_assignments_are_surfaced() -> None:
    body = '''
      const config = {
        sessionKey: "Qx7Lm2Vt9Bz4Nr6Ks1Yw3Hd8Pf5Jc0A",
        apiKey: "YOUR_API_KEY_HERE",
        greeting: "hello there friend"
      };
    '''
    found = high_entropy_candidates(body)
    assert "Qx7Lm2Vt9Bz4Nr6Ks1Yw3Hd8Pf5Jc0A" in found
    assert not any("YOUR_API_KEY" in value for value in found)
    assert not any("hello" in value for value in found)


# ── Reporting shape and budgeting ────────────────────────────────

def test_findings_fingerprint_rather_than_store_secrets() -> None:
    finding = SecretExposureTool._finding(
        "Exposed Stripe secret key", "critical", "https://x.example.com/app.js",
        STRIPE_KEY,
    )
    serialized = str(finding)
    assert STRIPE_KEY not in serialized
    assert finding["masked_value"].startswith("sk_")
    assert re.fullmatch(r"[0-9a-f]{16}", finding["secret_fingerprint"])


def test_scripts_and_config_files_get_budget_priority() -> None:
    candidates = (
        [f"https://x.example.com/page{index}" for index in range(500)]
        + ["https://x.example.com/app.js", "https://x.example.com/.env",
           "https://x.example.com/config.json", "https://x.example.com/main.js.map"]
    )
    ordered = SecretExposureTool._prioritised_urls(candidates)
    assert ordered[:4] == [
        "https://x.example.com/app.js", "https://x.example.com/.env",
        "https://x.example.com/config.json", "https://x.example.com/main.js.map",
    ]
    assert len(ordered) <= 400


def test_script_budget_is_capped_so_html_is_still_sampled() -> None:
    scripts = [f"https://x.example.com/{index}.js" for index in range(MAX_SCRIPT_URLS + 50)]
    pages = [f"https://x.example.com/page{index}" for index in range(50)]
    ordered = SecretExposureTool._prioritised_urls(scripts + pages)
    assert sum(1 for url in ordered if url.endswith(".js")) == MAX_SCRIPT_URLS
    assert any(url.endswith("page0") for url in ordered)
