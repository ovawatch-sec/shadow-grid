"""Tests for the cross-program scan listing endpoint.

The activity feed used to rebuild this client-side by listing programs and then
requesting each program's scans — 1+N requests per poll. These cover the single
endpoint that replaced it, plus the storage default that backs it.
"""
from __future__ import annotations

import asyncio

import pytest

import api.scans as scans_api
from models import Project, Scan
from storage.base import BaseStorage


class _FakeStore:
    def __init__(self, scans: list[Scan]) -> None:
        self._scans = scans

    async def list_all_scans(self) -> list[Scan]:
        return list(self._scans)


def _scan(project_id: str, created_at: str, **kw) -> Scan:
    return Scan(project_id=project_id, tools=["httpx"], created_at=created_at, **kw)


@pytest.fixture
def rows() -> list[Scan]:
    return [
        _scan("p1", "2026-01-01T00:00:00Z"),
        _scan("p2", "2026-03-01T00:00:00Z"),
        _scan("p1", "2026-02-01T00:00:00Z"),
    ]


def test_lists_scans_from_every_program(monkeypatch, rows):
    monkeypatch.setattr(scans_api, "_get_storage", lambda: _FakeStore(rows))
    result = asyncio.run(scans_api.list_all_scans())
    assert len(result) == 3
    assert {row["project_id"] for row in result} == {"p1", "p2"}


def test_newest_scan_comes_first(monkeypatch, rows):
    monkeypatch.setattr(scans_api, "_get_storage", lambda: _FakeStore(rows))
    result = asyncio.run(scans_api.list_all_scans())
    assert [row["created_at"] for row in result] == sorted(
        (row["created_at"] for row in result), reverse=True
    )
    assert result[0]["project_id"] == "p2"


def test_custom_header_values_are_not_leaked(monkeypatch):
    """The listing goes through the same redaction as the single-scan reads."""
    scan = _scan("p1", "2026-01-01T00:00:00Z", custom_headers={"Authorization": "Bearer secret"})
    monkeypatch.setattr(scans_api, "_get_storage", lambda: _FakeStore([scan]))
    result = asyncio.run(scans_api.list_all_scans())
    assert result[0]["custom_headers"] == {"Authorization": "********"}
    assert "secret" not in str(result)


def test_storage_default_walks_every_program():
    """A backend implementing only the abstract surface still returns everything."""

    class _WalkingStore(BaseStorage):
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def list_projects(self) -> list[Project]:
            return [Project(id="p1", name="One"), Project(id="p2", name="Two")]

        async def list_scans(self, project_id: str) -> list[Scan]:
            self.calls.append(project_id)
            return [_scan(project_id, "2026-01-01T00:00:00Z")]

        def __getattr__(self, name):  # unused abstract members
            raise AttributeError(name)

    _WalkingStore.__abstractmethods__ = frozenset()
    store = _WalkingStore()
    result = asyncio.run(store.list_all_scans())
    assert store.calls == ["p1", "p2"]
    assert [scan.project_id for scan in result] == ["p1", "p2"]
