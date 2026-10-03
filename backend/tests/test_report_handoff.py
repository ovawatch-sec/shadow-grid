"""Exports that hand the discovered surface to manual testing tools."""
from __future__ import annotations

from datetime import datetime, timezone

from api.reports import _har_document, _target_urls
from inventory import AssetType, InventoryAsset, InventorySnapshot


def _asset(asset_type: AssetType, value: str, sources: list[str] | None = None) -> InventoryAsset:
    now = datetime.now(timezone.utc)
    return InventoryAsset(
        id=value, type=asset_type, value=value, first_seen=now, last_seen=now,
        sources=sources or ["param_miner"],
    )


SNAPSHOT = InventorySnapshot(scan_id="s1", project_id="p1", assets=[
    _asset(AssetType.URL, "https://example.com/search?q=a"),
    _asset(AssetType.ENDPOINT, "POST https://api.example.com/orders"),
    _asset(AssetType.ENDPOINT, "GET https://example.com/search?q=a"),
    _asset(AssetType.HOSTNAME, "example.com"),
    _asset(AssetType.PARAMETER, "https://example.com/search?q"),
])


def test_target_list_holds_only_fetchable_urls() -> None:
    urls = _target_urls(SNAPSHOT)
    assert urls == ["https://example.com/search?q=a", "https://api.example.com/orders"]
    assert all(url.startswith("http") for url in urls)


def test_har_records_method_and_query_for_replay() -> None:
    entries = _har_document("Acme", SNAPSHOT)["log"]["entries"]
    by_url = {entry["request"]["url"]: entry["request"] for entry in entries}
    assert by_url["https://api.example.com/orders"]["method"] == "POST"
    search = by_url["https://example.com/search?q=a"]
    assert search["queryString"] == [{"name": "q", "value": "a"}]
    assert {"name": "Host", "value": "example.com"} in search["headers"]


def test_har_is_structurally_valid() -> None:
    log = _har_document("Acme", SNAPSHOT)["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "ShadowGrid"
    for entry in log["entries"]:
        assert {"startedDateTime", "request", "response", "cache", "timings"} <= set(entry)
        # Responses are empty by design: these are requests to replay, not
        # captured traffic.
        assert entry["response"]["status"] == 0


def test_non_http_assets_are_excluded() -> None:
    document = _har_document("Acme", SNAPSHOT)
    assert len(document["log"]["entries"]) == 3
