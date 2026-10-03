"""AI analysis prompt construction and evidence context."""
from __future__ import annotations

import json

from tools.analysis.ai_analysis import (
    ARTIFACT_SOURCES,
    GENERIC_AI_PROMPT,
    MAX_CONTEXT_CHARS,
    MAX_ROW_CHARS,
    AIAnalysisTool,
    _all_rows,
)


def _domain_dir(tmp_path, files: dict[str, str]):
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir(exist_ok=True)
    for name, body in files.items():
        (domain_dir / name).write_text(body, encoding="utf-8")
    return domain_dir


def _context(tmp_path, files: dict[str, str]):
    domain_dir = _domain_dir(tmp_path, files)
    tool = AIAnalysisTool(tmp_path, tmp_path)
    return tool, domain_dir, tool._build_context("example.com", domain_dir)


# ── Prompt contract ──────────────────────────────────────────────

def test_prompt_is_fully_rendered() -> None:
    assert "{legend}" not in GENERIC_AI_PROMPT
    assert "params" in GENERIC_AI_PROMPT and "risk_hints" in GENERIC_AI_PROMPT


def test_prompt_demands_citations_and_forbids_invention() -> None:
    assert "[nuclei]" in GENERIC_AI_PROMPT
    assert "cannot cite" in GENERIC_AI_PROMPT
    assert "never name a CVE that is not already in the context" in GENERIC_AI_PROMPT
    assert "Inferred:" in GENERIC_AI_PROMPT


def test_prompt_handles_thin_evidence_instead_of_padding() -> None:
    assert "No supporting evidence in this assessment." in GENERIC_AI_PROMPT
    assert "Do not restate the input" in GENERIC_AI_PROMPT


def test_prompt_constrains_scope_and_destructiveness() -> None:
    for rule in ("non-destructive", "denial of service", "brute force", "third-party"):
        assert rule in GENERIC_AI_PROMPT


def test_prompt_declares_every_required_section() -> None:
    for section in ("## Verdict", "## Priority Test Surface", "## Attack Paths",
                    "## Gaps In This Assessment", "## Noise"):
        assert section in GENERIC_AI_PROMPT


def test_prompt_explains_truncation_so_counts_are_not_invented() -> None:
    assert "TRUNCATED" in GENERIC_AI_PROMPT
    assert "Never\nstate a count you cannot read from `total`" in GENERIC_AI_PROMPT


# ── Context assembly ─────────────────────────────────────────────

def test_artifact_filenames_match_what_tools_write(tmp_path) -> None:
    # whatweb writes JSONL, not .txt — the old map silently read nothing.
    sources = {key: filename for key, filename, _cap in ARTIFACT_SOURCES}
    assert sources["whatweb"] == "whatweb.jsonl"
    assert sources["params"] == "params.txt"
    assert sources["api_endpoints"] == "api_endpoints.txt"
    assert sources["nuclei"] == "nuclei_results.jsonl"


def test_appsec_artifacts_reach_the_model(tmp_path) -> None:
    _tool, _dir, context = _context(tmp_path, {
        "params.txt": "https://example.com/item?id=1\n",
        "api_endpoints.txt": "POST https://api.example.com/orders\n",
        "whatweb.jsonl": json.dumps({"target": "https://example.com"}) + "\n",
    })
    for key in ("params", "api_endpoints", "whatweb"):
        assert context["artifacts"][key]["exists"], key
        assert context["artifacts"][key]["sample"]


def test_json_arrays_become_one_row_per_record(tmp_path) -> None:
    payload = [{"endpoint": "https://example.com/a"}, {"endpoint": "https://example.com/b"}]
    _tool, _dir, context = _context(tmp_path, {"param_miner.json": json.dumps(payload)})
    assert context["artifacts"]["param_endpoints"]["total"] == 2


def test_broken_json_falls_back_to_lines(tmp_path) -> None:
    domain_dir = _domain_dir(tmp_path, {"api_spec.json": "{not json"})
    assert _all_rows(domain_dir / "api_spec.json") == ["{not json"]


def test_absent_artifacts_are_reported_not_hidden(tmp_path) -> None:
    _tool, _dir, context = _context(tmp_path, {"params.txt": "https://example.com/a?b=1\n"})
    assert context["artifacts"]["nuclei"]["exists"] is False
    assert context["artifacts"]["nuclei"]["total"] == 0


def test_empty_file_counts_as_absent(tmp_path) -> None:
    _tool, _dir, context = _context(tmp_path, {"nuclei_results.jsonl": "\n\n"})
    assert context["artifacts"]["nuclei"]["exists"] is False


# ── Budgeting ────────────────────────────────────────────────────

def test_sampling_is_capped_and_flagged(tmp_path) -> None:
    body = "\n".join(f"https://example.com/{index}?a=1" for index in range(5_000))
    _tool, _dir, context = _context(tmp_path, {"params.txt": body})
    artifact = context["artifacts"]["params"]
    assert artifact["total"] == 5_000
    assert artifact["truncated"] is True
    assert len(artifact["sample"]) <= 120


def test_long_rows_are_trimmed(tmp_path) -> None:
    _tool, _dir, context = _context(tmp_path, {"nuclei_results.jsonl": "x" * 5_000 + "\n"})
    assert len(context["artifacts"]["nuclei"]["sample"][0]) == MAX_ROW_CHARS


def test_whole_context_stays_within_budget(tmp_path) -> None:
    noisy = "\n".join(f"https://example.com/{index}/{'p' * 200}" for index in range(5_000))
    files = {filename: noisy for _key, filename, _cap in ARTIFACT_SOURCES if filename.endswith(".txt")}
    _tool, _dir, context = _context(tmp_path, files)
    sampled = sum(
        len(row) for artifact in context["artifacts"].values() for row in artifact["sample"]
    )
    assert sampled <= MAX_CONTEXT_CHARS


def test_high_value_artifacts_are_funded_before_noisy_ones(tmp_path) -> None:
    noisy = "\n".join(f"https://example.com/{index}/{'p' * 250}" for index in range(10_000))
    _tool, _dir, context = _context(tmp_path, {
        "params.txt": "https://example.com/item?id=1\n",
        "waybackurls.txt": noisy,
        "gau.txt": noisy,
    })
    # The parameter surface is sampled first, so noise cannot crowd it out.
    assert context["artifacts"]["params"]["sample"] == ["https://example.com/item?id=1"]


# ── Prompt assembly ──────────────────────────────────────────────

def test_prompt_names_the_target_and_the_empty_artifacts(tmp_path) -> None:
    tool, _dir, context = _context(tmp_path, {"params.txt": "https://example.com/a?b=1\n"})
    prompt = tool._build_prompt("example.com", context)
    assert "Target domain: example.com" in prompt
    assert "Artifacts with no data" in prompt
    assert "nuclei" in prompt.split("```json")[0]
    assert '"domain":"example.com"' in prompt


def test_prompt_reports_none_when_every_artifact_has_data(tmp_path) -> None:
    files = {filename: "row\n" for _key, filename, _cap in ARTIFACT_SOURCES}
    tool, _dir, context = _context(tmp_path, files)
    prompt = tool._build_prompt("example.com", context)
    assert "Artifacts with no data (tool did not run, or returned nothing): none" in prompt


# ── Fallback ─────────────────────────────────────────────────────

def test_fallback_mirrors_the_requested_sections_and_is_honest(tmp_path) -> None:
    tool, _dir, context = _context(tmp_path, {"params.txt": "https://example.com/a?b=1\n"})
    markdown = tool._fallback_markdown("example.com", context, "PROMPT-BODY", "connection refused")
    assert "## Verdict" in markdown and "## Priority Test Surface" in markdown
    assert "none of it is analysis" in markdown
    assert "connection refused" in markdown
    # The prompt is embedded so the operator can run it elsewhere.
    assert "PROMPT-BODY" in markdown
