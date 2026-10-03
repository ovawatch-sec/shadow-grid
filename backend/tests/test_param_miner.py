"""Endpoint pattern collapsing and parameter extraction."""
from __future__ import annotations

import asyncio

from tools.urls.param_miner import (
    ParamMinerTool,
    endpoint_pattern,
    normalize_segment,
    risk_hints_for,
    split_url,
)


def _run(tmp_path, urls, filename="gau.txt"):
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir(exist_ok=True)
    (domain_dir / filename).write_text("\n".join(urls) + "\n", encoding="utf-8")
    tool = ParamMinerTool(tmp_path, tmp_path)
    run = asyncio.run(tool.run("example.com", domain_dir, tmp_path, None, {}))
    return tool.parse(run, "example.com"), domain_dir


# ── Normalisation ────────────────────────────────────────────────

def test_identifier_segments_collapse() -> None:
    assert normalize_segment("12345") == "{id}"
    assert normalize_segment("550e8400-e29b-41d4-a716-446655440000") == "{id}"
    assert normalize_segment("9f86d081884c7d659a2feaa0c55ad015") == "{id}"
    assert normalize_segment("2024-01-31") == "{date}"
    assert normalize_segment("order7421abc") == "{id}"


def test_meaningful_segments_survive() -> None:
    assert normalize_segment("products") == "products"
    assert normalize_segment("app.min.js") == "app.min.js"
    assert normalize_segment("v2") == "v2"
    assert endpoint_pattern("/api/v2/orders/8821/items") == "/api/v2/orders/{id}/items"


def test_split_url_normalises_default_ports_and_drops_fragments() -> None:
    host, pattern, names, canonical = split_url("https://Example.com:443/a/1?b=2&a=1#frag")
    assert host == "example.com"
    assert pattern == "https://example.com/a/{id}"
    assert names == ["a", "b"]
    assert canonical == "https://example.com/a/1?b=2&a=1"


def test_split_url_rejects_non_http_values() -> None:
    assert split_url("ftp://example.com/x") is None
    assert split_url("javascript:alert(1)") is None
    assert split_url("") is None


# ── Risk hints ───────────────────────────────────────────────────

def test_risk_hints_flag_known_bug_classes() -> None:
    assert "ssrf_or_redirect" in risk_hints_for(["next"])
    assert "path_traversal" in risk_hints_for(["file"])
    assert "sql_injection" in risk_hints_for(["id"])
    assert risk_hints_for(["unrecognised_name"]) == []


# ── End-to-end behaviour ─────────────────────────────────────────

def test_thousands_of_ids_collapse_to_one_endpoint(tmp_path) -> None:
    urls = [f"https://example.com/product/{index}?id={index}&ref=x" for index in range(500)]
    rows, _ = _run(tmp_path, urls)
    assert len(rows) == 1
    assert rows[0]["endpoint"] == "https://example.com/product/{id}"
    assert rows[0]["params"] == ["id", "ref"]
    assert rows[0]["observed_urls"] == 500


def test_distinct_parameter_sets_stay_separate(tmp_path) -> None:
    rows, _ = _run(tmp_path, [
        "https://example.com/search?q=a",
        "https://example.com/search?q=a&page=2",
        "https://example.com/search",
    ])
    assert sorted(tuple(row["params"]) for row in rows) == [(), ("page", "q"), ("q",)]


def test_outputs_are_written_for_downstream_tools(tmp_path) -> None:
    rows, domain_dir = _run(tmp_path, [
        "https://example.com/redirect?next=https://evil.test",
        "https://example.com/static/app.js",
    ])
    params = (domain_dir / "params.txt").read_text().split()
    deduped = (domain_dir / "urls_deduped.txt").read_text().split()
    names = (domain_dir / "param_names.txt").read_text().split()
    # params.txt only carries fuzzable URLs; the static asset is not one.
    assert params == ["https://example.com/redirect?next=https://evil.test"]
    assert "https://example.com/static/app.js" in deduped
    assert names == ["next"]
    assert all(url.startswith("http") for url in deduped)


def test_parameterised_endpoints_sort_first(tmp_path) -> None:
    rows, _ = _run(tmp_path, [
        "https://example.com/plain",
        "https://example.com/one?a=1",
        "https://example.com/two?a=1&b=2",
    ])
    assert [row["param_count"] for row in rows] == [2, 1, 0]


def test_no_sources_reports_cleanly(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    tool = ParamMinerTool(tmp_path, tmp_path)
    run = asyncio.run(tool.run("example.com", domain_dir, tmp_path, None, {}))
    assert run.returncode == 0
    assert tool.parse(run, "example.com") == []
