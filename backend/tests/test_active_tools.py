"""Opt-in active-testing tools: gating, inputs, and output parsing."""
from __future__ import annotations

import asyncio
import json

from tools.http.vhost import VhostTool
from tools.registry import REGISTRY, default_tools, opt_in_tools
from tools.vuln.nuclei import parse_nuclei_jsonl
from tools.vuln.nuclei_dast import NucleiDastTool


# ── Gating ───────────────────────────────────────────────────────

def test_active_tools_are_excluded_from_the_default_selection() -> None:
    defaults = set(default_tools())
    assert {"nuclei_dast", "vhost"} == set(opt_in_tools())
    assert not (defaults & set(opt_in_tools()))
    # Everything else is still available by default.
    assert set(REGISTRY) - defaults == set(opt_in_tools())


def test_passive_analysis_tools_run_by_default() -> None:
    assert {"param_miner", "api_spec"} <= set(default_tools())


# ── nuclei_dast ──────────────────────────────────────────────────

def test_dast_skips_cleanly_without_a_parameter_surface(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    tool = NucleiDastTool(tmp_path, tmp_path)
    run = asyncio.run(tool.run("example.com", domain_dir, tmp_path, None, {}))
    assert run.returncode == 0
    assert "param_miner" in run.stderr
    assert tool.parse(run, "example.com") == []


def test_dast_results_are_tagged_with_their_source(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    (domain_dir / "nuclei_dast.jsonl").write_text(json.dumps({
        "template-id": "sqli-error-based",
        "info": {"name": "SQL injection", "severity": "high"},
        "host": "app.example.com",
        "matched-at": "https://app.example.com/item?id=1",
    }) + "\n", encoding="utf-8")
    tool = NucleiDastTool(tmp_path, tmp_path)
    rows = tool.parse(type("R", (), {"lines": [], "stdout": ""})(), "example.com")
    assert rows[0]["source"] == "nuclei_dast"
    assert rows[0]["severity"] == "high"


def test_nuclei_jsonl_parser_tolerates_corrupt_lines() -> None:
    rows = parse_nuclei_jsonl(["{bad json", "", "[]", json.dumps({"template-id": "ok"})])
    assert [row["template_id"] for row in rows] == ["ok"]


# ── vhost ────────────────────────────────────────────────────────

def test_vhost_targets_come_from_resolved_services(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    (domain_dir / "httpx.jsonl").write_text("\n".join([
        json.dumps({"url": "https://app.example.com", "a": ["203.0.113.5"]}),
        json.dumps({"url": "https://other.example.com", "a": ["203.0.113.5"]}),
        json.dumps({"url": "http://api.example.com:8080", "ip": "203.0.113.9"}),
        json.dumps({"url": "https://noip.example.com"}),
        "not json",
    ]) + "\n", encoding="utf-8")
    tool = VhostTool(tmp_path, tmp_path)
    targets = tool._service_targets(domain_dir)
    assert ("https", "203.0.113.5", "") in targets
    assert ("http", "203.0.113.9", "8080") in targets
    # One entry per unique (scheme, ip, port) — two hostnames on one IP collapse.
    assert len(targets) == 2


def test_vhost_skips_without_resolved_services(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    tool = VhostTool(tmp_path, tmp_path)
    run = asyncio.run(tool.run("example.com", domain_dir, tmp_path, None, {}))
    assert run.returncode == 0
    assert "No resolved service IPs" in run.stderr


def test_vhost_wordlist_is_bounded(tmp_path) -> None:
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    source = tmp_path / "huge.txt"
    source.write_text("\n".join(f"host{index}" for index in range(10_000)), encoding="utf-8")
    bounded = VhostTool(tmp_path, tmp_path)._bounded_wordlist(source, domain_dir)
    assert bounded != source
    assert len(bounded.read_text().splitlines()) == 5_000
