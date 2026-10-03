"""Endpoints and parameters as first-class inventory assets."""
from __future__ import annotations

from inventory import AssetType, build_inventory
from models import ToolCategory, ToolResult


def _result(tool: str, category: ToolCategory, data: list[dict]) -> ToolResult:
    return ToolResult(
        scan_id="s1", project_id="p1", tool=tool, category=category,
        domain="example.com", data=data,
    )


def _snapshot(results):
    return build_inventory("s1", "p1", ["example.com"], results)


def _assets(snapshot, asset_type: AssetType):
    return [asset for asset in snapshot.assets if asset.type == asset_type]


def test_parameterised_endpoints_become_assets() -> None:
    snapshot = _snapshot([_result("param_miner", ToolCategory.URL, [{
        "url": "https://example.com/item?id=1&ref=x",
        "host": "example.com",
        "endpoint": "https://example.com/item",
        "method": "GET",
        "params": ["id", "ref"],
        "param_count": 2,
        "risk_hints": ["sql_injection"],
        "state": "parameter_observed",
    }])])
    endpoints = _assets(snapshot, AssetType.ENDPOINT)
    parameters = _assets(snapshot, AssetType.PARAMETER)
    assert [asset.value for asset in endpoints] == ["GET https://example.com/item"]
    assert endpoints[0].attributes["risk_hints"] == ["sql_injection"]
    assert sorted(asset.attributes["name"] for asset in parameters) == ["id", "ref"]


def test_endpoint_links_to_its_parameters_and_host() -> None:
    snapshot = _snapshot([_result("param_miner", ToolCategory.URL, [{
        "url": "https://example.com/item?id=1",
        "endpoint": "https://example.com/item",
        "method": "GET", "params": ["id"], "param_count": 1,
    }])])
    kinds = {relationship.type for relationship in snapshot.relationships}
    assert {"accepts_parameter", "served_by", "instance_of"} <= kinds


def test_documented_api_endpoints_record_method_and_auth() -> None:
    snapshot = _snapshot([_result("api_spec", ToolCategory.HTTP, [{
        "url": "https://api.example.com/orders",
        "host": "api.example.com",
        "endpoint": "https://api.example.com/orders",
        "method": "POST", "params": ["sku"], "param_count": 1,
        "requires_auth": True, "spec_url": "https://api.example.com/openapi.json",
        "state": "endpoint_documented",
    }])])
    endpoint = _assets(snapshot, AssetType.ENDPOINT)[0]
    assert endpoint.value == "POST https://api.example.com/orders"
    assert endpoint.attributes["requires_auth"] is True
    assert endpoint.attributes["spec_url"].endswith("openapi.json")
    assert "endpoint_documented" in endpoint.states


def test_the_same_endpoint_from_two_tools_is_one_asset() -> None:
    row = {
        "endpoint": "https://example.com/search", "method": "GET",
        "params": ["q"], "param_count": 1, "url": "https://example.com/search?q=a",
    }
    snapshot = _snapshot([
        _result("param_miner", ToolCategory.URL, [row]),
        _result("api_spec", ToolCategory.HTTP, [dict(row)]),
    ])
    endpoints = _assets(snapshot, AssetType.ENDPOINT)
    assert len(endpoints) == 1
    assert endpoints[0].sources == ["api_spec", "param_miner"]


def test_a_dast_finding_attaches_to_the_tested_url() -> None:
    snapshot = _snapshot([
        _result("param_miner", ToolCategory.URL, [{
            "endpoint": "https://example.com/item", "method": "GET",
            "params": ["id"], "param_count": 1, "url": "https://example.com/item?id=1",
        }]),
        _result("nuclei_dast", ToolCategory.VULN, [{
            "template_id": "sqli-error", "name": "SQL injection", "severity": "high",
            "host": "example.com", "url": "https://example.com/item?id=1",
            "matched_at": "https://example.com/item?id=1",
        }]),
    ])
    finding = snapshot.findings[0]
    affected = {asset.id: asset for asset in snapshot.assets}[finding.asset_id]
    assert finding.title == "SQL injection"
    assert affected.type == AssetType.URL
    assert affected.value == "https://example.com/item?id=1"


def test_rows_without_endpoints_are_unaffected() -> None:
    snapshot = _snapshot([_result("httpx", ToolCategory.HTTP, [
        {"host": "example.com", "url": "https://example.com/", "port": 443},
    ])])
    assert _assets(snapshot, AssetType.ENDPOINT) == []
    assert _assets(snapshot, AssetType.PARAMETER) == []
