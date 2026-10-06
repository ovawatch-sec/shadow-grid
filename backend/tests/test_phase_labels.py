"""Phase labels must have exactly one source.

Handoff events (subdomain-merge, alive-subdomains, alive-urls) are emitted
outside ``_run_phase`` and used to restate the phase label as a literal. One
had drifted — the alive-urls handoff reported "HTTP Probing & Port Scanning"
for phase 4, which PHASES defines as "HTTP, TLS & Port Validation". The live
progress view groups by phase, so two names for one index split a phase across
two cards.
"""
from __future__ import annotations

import ast
from pathlib import Path

from scan_engine import PHASES, phase_name

ENGINE = Path(__file__).resolve().parents[1] / "scan_engine.py"


def _hardcoded_phase_labels() -> list[str]:
    """Every non-empty string literal passed as a `phase=` keyword argument."""
    tree = ast.parse(ENGINE.read_text())
    return [
        keyword.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "phase"
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
        and keyword.value.value != ""
    ]


def test_phase_name_matches_every_definition():
    for phase in PHASES:
        assert phase_name(int(phase["index"])) == str(phase["name"])


def test_unknown_index_falls_back_rather_than_raising():
    assert phase_name(99) == "Phase 99"


def test_phase_indices_are_unique():
    indices = [int(phase["index"]) for phase in PHASES]
    assert len(indices) == len(set(indices))


def test_no_phase_label_is_written_as_a_literal():
    """The check that would have caught the original drift.

    It fails again the moment a phase name is pasted into a new emit instead of
    being looked up.
    """
    assert _hardcoded_phase_labels() == []
