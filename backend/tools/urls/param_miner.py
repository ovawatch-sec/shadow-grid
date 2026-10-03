"""Collapse discovered URLs into a deduplicated, parameter-aware test surface.

URL discovery produces tens of thousands of near-identical links: the same
endpoint with a different row id, the same search page with a different term.
Nothing downstream can use that directly — a scanner pointed at the raw list
re-tests one endpoint thousands of times and still never learns which query
parameters exist.

This tool normalizes every discovered URL into an endpoint *pattern* (path
segments that look like identifiers collapse to ``{id}``), groups by
(host, pattern, parameter names), and keeps one concrete representative per
group. The result is the input a DAST pass actually needs, plus a parameter
name inventory for manual testing.

It runs entirely offline over files other tools already wrote — no requests,
no API keys, no binary.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from models import ToolCategory
from tools.base import BaseTool, RunResult

#: Files written by the URL discovery phase, in preference order.
URL_SOURCES = (
    "katana.txt", "gau.txt", "waybackurls.txt", "urlfinder.txt", "alive_urls.txt",
)

#: Upper bounds that keep a pathological wayback dump from flooding storage.
MAX_INPUT_URLS = 400_000
MAX_PARAM_URLS = 5_000
MAX_DEDUPED_URLS = 20_000

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NUMERIC_RE = re.compile(r"^\d+$")
#: A segment mixing digits and letters with enough digits to be a slug id.
MIXED_ID_RE = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{8,}$")

#: Parameter names worth testing first, grouped by the bug class they suggest.
#: These are hints for a human operator, not findings.
RISK_HINTS: dict[str, frozenset[str]] = {
    "ssrf_or_redirect": frozenset({
        "url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "return",
        "return_url", "returnurl", "continue", "dest", "destination", "callback",
        "target", "link", "site", "feed", "out", "image_url", "proxy", "fetch",
        "domain", "host", "forward", "to", "goto", "rurl",
    }),
    "path_traversal": frozenset({
        "file", "filename", "filepath", "path", "folder", "dir", "document", "doc",
        "template", "include", "load", "read", "download", "page", "pg", "style",
        "content", "root", "attachment", "resource",
    }),
    "sql_injection": frozenset({
        "id", "uid", "user_id", "userid", "pid", "cat", "category", "item", "order",
        "sort", "where", "query", "filter", "select", "table", "column", "keyword",
        "year", "num", "offset", "limit", "group", "report", "process",
    }),
    "reflected_xss": frozenset({
        "q", "s", "search", "query", "keyword", "term", "name", "message", "comment",
        "text", "title", "lang", "callback", "jsonp", "ref", "tag", "value",
    }),
    "command_injection": frozenset({
        "cmd", "exec", "command", "run", "ping", "ip", "code", "do", "func",
        "action", "option", "arg", "shell", "script",
    }),
    "template_injection": frozenset({
        "template", "tpl", "view", "theme", "layout", "preview", "render", "format",
    }),
    "access_control": frozenset({
        "account", "profile", "user", "username", "order_id", "invoice", "doc_id",
        "customer", "company", "org", "team", "role", "admin", "impersonate",
    }),
}


def normalize_segment(segment: str) -> str:
    """Return ``{id}`` for a path segment that is an identifier, else the segment."""
    if not segment:
        return segment
    if NUMERIC_RE.match(segment) or UUID_RE.match(segment) or HEX_RE.match(segment):
        return "{id}"
    if DATE_RE.match(segment):
        return "{date}"
    # A long mixed-case token with digits is almost always a slug or hash id,
    # but a filename with an extension stays as-is: /app.min.js matters.
    if "." not in segment and MIXED_ID_RE.match(segment):
        return "{id}"
    return segment


def endpoint_pattern(path: str) -> str:
    """Collapse identifier-looking path segments so one route groups together."""
    segments = [normalize_segment(segment) for segment in (path or "/").split("/")]
    pattern = "/".join(segments)
    return pattern or "/"


def split_url(value: str) -> tuple[str, str, list[str], str] | None:
    """Return (host, pattern, sorted param names, canonical URL) for one URL."""
    candidate = (value or "").strip()
    if not candidate.lower().startswith(("http://", "https://")):
        return None
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme.lower()
    if (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443):
        port = ""
    path = parsed.path or "/"
    names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
    canonical = urlunsplit((scheme, f"{host}{port}", path, parsed.query, ""))
    return host, f"{scheme}://{host}{port}{endpoint_pattern(path)}", names, canonical


def risk_hints_for(names: list[str]) -> list[str]:
    """Return the bug classes suggested by a set of parameter names."""
    lowered = {name.lower() for name in names}
    return sorted(
        label for label, candidates in RISK_HINTS.items() if lowered & candidates
    )


class ParamMinerTool(BaseTool):
    """Build the deduplicated endpoint and parameter surface for a domain."""

    name = "param_miner"
    binary_name = None
    category = ToolCategory.URL
    description = "Endpoint/parameter extraction and URL pattern dedup (offline)"
    parallel_group = "analysis"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        raw: list[str] = []
        for filename in URL_SOURCES:
            raw.extend(self._read_lines(out_dir / filename))
            if len(raw) >= MAX_INPUT_URLS:
                break
        if not raw:
            return RunResult("", "No discovered URLs to analyse", 0, 0)

        groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
        param_names: dict[str, int] = {}

        for value in raw[:MAX_INPUT_URLS]:
            parsed = split_url(value)
            if parsed is None:
                continue
            host, pattern, names, canonical = parsed
            key = (host, pattern, tuple(names))
            group = groups.get(key)
            if group is None:
                group = {
                    "url": canonical,
                    "host": host,
                    "endpoint": pattern,
                    "method": "GET",
                    "params": names,
                    "param_count": len(names),
                    "risk_hints": risk_hints_for(names),
                    "observed_urls": 0,
                    "source": "param_miner",
                    "state": "parameter_observed" if names else "endpoint_observed",
                }
                groups[key] = group
            group["observed_urls"] += 1
            for name in names:
                param_names[name] = param_names.get(name, 0) + 1

        rows = sorted(
            groups.values(),
            # Parameterised endpoints first, then the most frequently observed.
            key=lambda row: (-row["param_count"], -row["observed_urls"], row["endpoint"]),
        )
        param_urls = [row["url"] for row in rows if row["param_count"]][:MAX_PARAM_URLS]
        # One concrete, fetchable representative per endpoint group — this is
        # what gets handed to a browser, Burp, or Caido.
        representatives = [row["url"] for row in rows][:MAX_DEDUPED_URLS]

        self._write_list(out_dir / "params.txt", param_urls)
        self._write_list(out_dir / "urls_deduped.txt", representatives)
        self._write_list(
            out_dir / "param_names.txt",
            [name for name, _ in sorted(param_names.items(), key=lambda item: (-item[1], item[0]))],
        )
        serialized = json.dumps(rows)
        (out_dir / "param_miner.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "", 0, 0)

    @staticmethod
    def _write_list(path: Path, values: list[str]) -> None:
        path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        payload = result.stdout or ""
        if not payload:
            path = self.output_dir / domain / "param_miner.json"
            payload = path.read_text(encoding="utf-8") if path.is_file() else "[]"
        try:
            rows = json.loads(payload)
        except json.JSONDecodeError:
            return []
        return rows if isinstance(rows, list) else []
