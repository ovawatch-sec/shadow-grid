"""OpenAPI flattening, GraphQL introspection handling, and service roots."""
from __future__ import annotations

from tools.http.api_spec import graphql_fields, parse_openapi, service_roots

OPENAPI_V3 = {
    "openapi": "3.0.1",
    "info": {"title": "Orders API"},
    "paths": {
        "/orders/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {
                "parameters": [{"name": "expand", "in": "query"}],
                "security": [{"bearer": []}],
            },
            "delete": {},
        },
        "/orders": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"properties": {"sku": {}, "quantity": {}}}
                        }
                    }
                }
            }
        },
        "/health": {"get": {}},
    },
}

SWAGGER_V2 = {
    "swagger": "2.0",
    "paths": {"/legacy": {"get": {"parameters": [{"name": "page", "in": "query"}]}}},
}


def _by_endpoint(rows):
    return {f"{row['method']} {row['endpoint']}": row for row in rows}


def test_openapi_v3_flattens_methods_and_parameters() -> None:
    rows = _by_endpoint(parse_openapi(OPENAPI_V3, "https://api.example.com", "https://api.example.com/openapi.json"))
    assert set(rows) == {
        "GET https://api.example.com/orders/{id}",
        "DELETE https://api.example.com/orders/{id}",
        "POST https://api.example.com/orders",
        "GET https://api.example.com/health",
    }
    # Path-level parameters apply to every operation on that path.
    assert rows["GET https://api.example.com/orders/{id}"]["params"] == ["expand", "id"]
    assert rows["DELETE https://api.example.com/orders/{id}"]["params"] == ["id"]


def test_json_request_body_properties_count_as_parameters() -> None:
    rows = _by_endpoint(parse_openapi(OPENAPI_V3, "https://api.example.com", "spec"))
    assert rows["POST https://api.example.com/orders"]["params"] == ["quantity", "sku"]


def test_declared_security_is_recorded() -> None:
    rows = _by_endpoint(parse_openapi(OPENAPI_V3, "https://api.example.com", "spec"))
    assert rows["GET https://api.example.com/orders/{id}"]["requires_auth"] is True
    assert rows["GET https://api.example.com/health"]["requires_auth"] is False


def test_swagger_v2_is_supported() -> None:
    rows = parse_openapi(SWAGGER_V2, "https://api.example.com", "spec")
    assert rows[0]["spec_version"] == "2.0"
    assert rows[0]["params"] == ["page"]


def test_non_specifications_yield_nothing() -> None:
    assert parse_openapi({"message": "not a spec"}, "https://x", "s") == []
    assert parse_openapi("<html></html>", "https://x", "s") == []
    assert parse_openapi({"paths": "broken"}, "https://x", "s") == []


def test_graphql_introspection_fields_are_extracted() -> None:
    payload = {"data": {"__schema": {
        "queryType": {"name": "Query", "fields": [{"name": "user"}, {"name": "orders"}]},
        "mutationType": {"name": "Mutation", "fields": [{"name": "deleteUser"}]},
    }}}
    queries, mutations = graphql_fields(payload)
    assert queries == ["user", "orders"]
    assert mutations == ["deleteUser"]


def test_disabled_introspection_reports_nothing() -> None:
    assert graphql_fields({"errors": [{"message": "introspection disabled"}]}) == ([], [])
    assert graphql_fields({"data": {}}) == ([], [])
    assert graphql_fields(None) == ([], [])


def test_service_roots_are_unique_and_capped() -> None:
    roots = service_roots([
        "https://a.example.com/one", "https://a.example.com/two",
        "http://a.example.com/three", "https://b.example.com:8443/x",
        "ftp://c.example.com", "garbage",
    ])
    assert roots == [
        "https://a.example.com", "http://a.example.com", "https://b.example.com:8443",
    ]
    assert len(service_roots([f"https://h{i}.example.com/" for i in range(100)], limit=5)) == 5
