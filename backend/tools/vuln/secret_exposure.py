"""Detect exposed secrets in bounded response samples without storing values."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

MAX_BODY_BYTES = 1_000_000
#: JavaScript bundles hold the majority of leaked keys, so they are inspected
#: first and are never crowded out by HTML pages when the budget runs short.
MAX_URLS = 400
MAX_SCRIPT_URLS = 250
#: Shannon entropy above this, at this length, is a credential rather than prose.
ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_LENGTH = 24

PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"), "high"),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b"), "high"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/-]{10,}"), "medium"),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"), "high"),
    ("Google service account key", re.compile(r'"type"\s*:\s*"service_account"'), "critical"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "high"),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "high"),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    ("PyPI upload token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"), "high"),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"), "high"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b"), "high"),
    ("Azure storage key", re.compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{40,})"), "critical"),
    ("Database connection string", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s:@/]{4,})@"), "critical"),
    ("Basic authorization header", re.compile(r"(?i)\bauthorization\s*[:=]\s*['\"]?Basic\s+([A-Za-z0-9+/=]{16,})"), "high"),
    ("Bearer token", re.compile(r"(?i)\bauthorization\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9._~+/-]{20,})"), "medium"),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("Firebase database URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "low"),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*['\"]([^'\"\s]{8,})"), "medium"),
)

#: Placeholders that appear in documentation and bundled examples. Reporting
#: these as leaked credentials trains an operator to ignore the tool.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{4,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|"
    r"(?:your|my|the|a)[_-]?(?:api)?[_-]?(?:key|token|secret|password)|"
    r"changeme|example|placeholder|dummy|sample|test|redacted|null|none|undefined|true|false)$"
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    """Return True for documentation placeholders rather than real credentials."""
    candidate = (value or "").strip()
    if len(candidate) < 8:
        return True
    if PLACEHOLDER_RE.match(candidate):
        return True
    # A single repeated character, or an obvious sequence, is never a secret.
    return len(set(candidate)) <= 2


def high_entropy_candidates(text: str) -> list[str]:
    """Return assigned values that look like random credential material."""
    found: list[str] = []
    for match in ASSIGNMENT_RE.finditer(text):
        value = match.group(2)
        if len(value) < ENTROPY_MIN_LENGTH or is_placeholder(value):
            continue
        if shannon_entropy(value) >= ENTROPY_THRESHOLD:
            found.append(value)
        if len(found) >= 5:
            break
    return found


#: ``name = "value"`` in JSON, JS, and config syntax.
ASSIGNMENT_RE = re.compile(r"""([A-Za-z0-9_.-]{3,40})\s*[:=]\s*["']([A-Za-z0-9+/=_.~-]{16,200})["']""")


class SecretExposureTool(BaseTool):
    """Inspect discovered in-scope content and persist fingerprints, never secrets."""

    name = "secret_exposure"
    binary_name = None
    category = ToolCategory.VULN
    description = "Masked secret and credential exposure detection"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        candidates = self._read_lines(out_dir / "alive_urls.txt")
        for filename in (
            "katana.txt", "urls_deduped.txt", "gau.txt", "waybackurls.txt", "urlfinder.txt",
        ):
            candidates.extend(self._read_lines(out_dir / filename))
        urls = self._prioritised_urls(candidates)
        findings: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(10)
        timeout = aiohttp.ClientTimeout(total=15)

        async def inspect(url: str, session: aiohttp.ClientSession) -> None:
            async with semaphore:
                try:
                    async with session.get(
                        url, allow_redirects=True,
                        headers=self._headers_for_host(self._host_of(url)),
                    ) as response:
                        if response.status >= 400:
                            return
                        raw = await response.content.read(MAX_BODY_BYTES)
                        text = raw.decode(errors="replace")
                        final_url = str(response.url)
                        matched: set[str] = set()
                        for name, pattern, severity in PATTERNS:
                            match = pattern.search(text)
                            if not match:
                                continue
                            secret = match.group(1) if match.lastindex else match.group(0)
                            if is_placeholder(secret):
                                continue
                            matched.add(secret)
                            findings.append(
                                self._finding(f"Exposed {name}", severity, final_url, secret)
                            )
                        # Anything that survives entropy scoring is credential
                        # material a named pattern does not cover yet.
                        for value in high_entropy_candidates(text):
                            if value in matched:
                                continue  # already reported under its own pattern
                            findings.append(self._finding(
                                "High-entropy value exposed in response", "low", final_url, value,
                                extra_data={"entropy": round(shannon_entropy(value), 2)},
                            ))
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(inspect(url, session) for url in urls))
        serialized = json.dumps(findings)
        (out_dir / "secret_exposure.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "", 0, 0)

    @staticmethod
    def _prioritised_urls(candidates: list[str]) -> list[str]:
        """Return the inspection budget, scripts and config files first."""
        unique = list(dict.fromkeys(
            url for url in candidates if url.startswith(("http://", "https://"))
        ))
        scripts, others = [], []
        for url in unique:
            path = url.split("?", 1)[0].lower()
            target = scripts if path.endswith((
                ".js", ".mjs", ".jsx", ".ts", ".map", ".json", ".env", ".yml", ".yaml", ".config",
            )) else others
            target.append(url)
        budget = scripts[:MAX_SCRIPT_URLS]
        return budget + others[:max(0, MAX_URLS - len(budget))]

    @staticmethod
    def _finding(name: str, severity: str, url: str, secret: str,
                 extra_data: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build one finding that records a fingerprint, never the secret."""
        return {
            "name": name, "severity": severity, "url": url, "matched_at": url,
            "secret_fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:16],
            "masked_value": f"{secret[:3]}***{secret[-2:]}" if len(secret) >= 7 else "***",
            "source": "secret_exposure", "state": "finding_observed",
            **(extra_data or {}),
        }

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Return masked findings without raw response bodies or credentials."""
        try:
            value = json.loads(result.stdout or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []
