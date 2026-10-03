"""Discover machine-readable API definitions and map them to endpoints.

Content discovery guesses paths one request at a time. An OpenAPI document or
an introspectable GraphQL schema hands over the whole application surface at
once: every route, method, parameter, and which of them expect credentials.
For an API-first target this is the highest-signal request in the pipeline.

Findings are limited to what is demonstrably exposed — the specification
itself, or an introspection response. Nothing here exercises the documented
endpoints.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

#: Conventional locations for an OpenAPI/Swagger document.
SPEC_PATHS = (
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/docs/v1",
    "/openapi.json", "/openapi.yaml", "/api/openapi.json", "/api/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs", "/v2/api-docs",
    "/api-docs", "/api/v1/openapi.json", "/api/docs.json", "/docs/openapi.json",
    "/.well-known/openapi.json", "/swagger-resources",
)

#: Conventional GraphQL entry points.
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql")

#: One cheap introspection probe — enough to prove the schema is readable
#: without pulling an entire type system over the wire.
INTROSPECTION_QUERY = (
    "{__schema{queryType{name fields{name}} mutationType{name fields{name}}}}"
)

MAX_ROOTS = 40
MAX_BODY_BYTES = 2_000_000
MAX_ENDPOINTS = 2_000
HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


def service_roots(urls: list[str], limit: int = MAX_ROOTS) -> list[str]:
    """Reduce a URL list to unique ``scheme://host[:port]`` service roots."""
    roots: dict[str, None] = {}
    for value in urls:
        try:
            parsed = urlsplit((value or "").strip())
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        roots.setdefault(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")), None)
        if len(roots) >= limit:
            break
    return list(roots)


def parse_openapi(document: Any, base: str, spec_url: str) -> list[dict[str, Any]]:
    """Flatten an OpenAPI 2/3 document into endpoint rows."""
    if not isinstance(document, dict):
        return []
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return []
    version = str(document.get("openapi") or document.get("swagger") or "unknown")
    title = str((document.get("info") or {}).get("title") or "")[:200]
    host = urlsplit(base).hostname or ""
    rows: list[dict[str, Any]] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict) or not isinstance(path, str):
            continue
        shared = operations.get("parameters") if isinstance(operations.get("parameters"), list) else []
        for method, operation in operations.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            declared = operation.get("parameters")
            declared = declared if isinstance(declared, list) else []
            names: list[str] = []
            for parameter in [*shared, *declared]:
                if isinstance(parameter, dict) and parameter.get("name"):
                    names.append(str(parameter["name"]))
            names.extend(_request_body_fields(operation.get("requestBody")))
            security = operation.get("security", document.get("security"))
            rows.append({
                "url": f"{base.rstrip('/')}{path}",
                "host": host,
                "endpoint": f"{base.rstrip('/')}{path}",
                "method": method.upper(),
                "params": sorted(dict.fromkeys(names)),
                "param_count": len(set(names)),
                "spec_url": spec_url,
                "spec_version": version,
                "spec_title": title,
                "requires_auth": bool(security),
                "source": "api_spec",
                "state": "endpoint_documented",
            })
            if len(rows) >= MAX_ENDPOINTS:
                return rows
    return rows


def _request_body_fields(request_body: Any) -> list[str]:
    """Return top-level JSON body property names declared for an operation."""
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    names: list[str] = []
    for media_type, media in content.items():
        if "json" not in str(media_type).lower() or not isinstance(media, dict):
            continue
        schema = media.get("schema")
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if isinstance(properties, dict):
            names.extend(str(name) for name in properties)
    return names


def graphql_fields(payload: Any) -> tuple[list[str], list[str]]:
    """Return (query fields, mutation fields) from an introspection response."""
    schema = ((payload or {}).get("data") or {}).get("__schema") if isinstance(payload, dict) else None
    if not isinstance(schema, dict):
        return [], []

    def names(node: Any) -> list[str]:
        fields = node.get("fields") if isinstance(node, dict) else None
        if not isinstance(fields, list):
            return []
        return [str(field.get("name")) for field in fields if isinstance(field, dict) and field.get("name")]

    return names(schema.get("queryType")), names(schema.get("mutationType"))


class ApiSpecTool(BaseTool):
    """Probe for OpenAPI documents and introspectable GraphQL endpoints."""

    name = "api_spec"
    binary_name = None
    category = ToolCategory.HTTP
    description = "OpenAPI/Swagger discovery and GraphQL introspection checks"
    parallel_group = "analysis"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        roots = service_roots(self._read_lines(out_dir / "alive_urls.txt"))
        if not roots:
            return RunResult("", "No verified alive services", 0, 0)

        rows: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(8)
        timeout = aiohttp.ClientTimeout(total=20)

        async def fetch_spec(session: aiohttp.ClientSession, base: str, path: str) -> None:
            url = f"{base}{path}"
            host = self._host_of(base)
            async with semaphore:
                try:
                    async with session.get(
                        url, allow_redirects=True, headers=self._headers_for_host(host),
                    ) as response:
                        if response.status != 200:
                            return
                        raw = await response.content.read(MAX_BODY_BYTES)
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return
            try:
                document = json.loads(raw.decode(errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            endpoints = parse_openapi(document, base, url)
            if not endpoints:
                return
            rows.append({
                "url": url, "host": host, "matched_at": url,
                "name": "API specification exposed",
                "severity": "low",
                "endpoint_count": len(endpoints),
                "spec_version": endpoints[0].get("spec_version", ""),
                "spec_title": endpoints[0].get("spec_title", ""),
                "source": "api_spec", "state": "finding_observed",
            })
            rows.extend(endpoints)

        async def probe_graphql(session: aiohttp.ClientSession, base: str, path: str) -> None:
            url = f"{base}{path}"
            host = self._host_of(base)
            headers = {**self._headers_for_host(host), "Content-Type": "application/json"}
            async with semaphore:
                try:
                    async with session.post(
                        url, json={"query": INTROSPECTION_QUERY},
                        allow_redirects=True, headers=headers,
                    ) as response:
                        if response.status >= 400:
                            return
                        raw = await response.content.read(MAX_BODY_BYTES)
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return
            try:
                payload = json.loads(raw.decode(errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            queries, mutations = graphql_fields(payload)
            if not queries and not mutations:
                return
            rows.append({
                "url": url, "host": host, "matched_at": url,
                "name": "GraphQL introspection enabled",
                "severity": "medium",
                "query_fields": len(queries), "mutation_fields": len(mutations),
                "source": "api_spec", "state": "finding_observed",
            })
            for operation, fields in (("QUERY", queries), ("MUTATION", mutations)):
                for field in fields[:200]:
                    rows.append({
                        "url": url, "host": host, "endpoint": f"{url}#{field}",
                        "method": operation, "params": [], "param_count": 0,
                        "source": "api_spec", "state": "endpoint_documented",
                    })

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(
                *(fetch_spec(session, base, path) for base in roots for path in SPEC_PATHS),
                *(probe_graphql(session, base, path) for base in roots for path in GRAPHQL_PATHS),
            )

        serialized = json.dumps(rows)
        (out_dir / "api_spec.json").write_text(serialized, encoding="utf-8")
        self._write_endpoint_list(out_dir, rows)
        return RunResult(serialized, "", 0, 0)

    @staticmethod
    def _write_endpoint_list(out_dir: Path, rows: list[dict[str, Any]]) -> None:
        """Write documented endpoints so later phases can target them."""
        lines = [
            f"{row['method']} {row['endpoint']}"
            for row in rows if row.get("state") == "endpoint_documented"
        ]
        (out_dir / "api_endpoints.txt").write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8",
        )

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        payload = result.stdout or ""
        if not payload:
            path = self.output_dir / domain / "api_spec.json"
            payload = path.read_text(encoding="utf-8") if path.is_file() else "[]"
        try:
            rows = json.loads(payload)
        except json.JSONDecodeError:
            return []
        return rows if isinstance(rows, list) else []
