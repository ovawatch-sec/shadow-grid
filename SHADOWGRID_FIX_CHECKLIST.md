# ShadowGrid Bug Fix Checklist

## Scope bugs addressed

- [x] Enforce deterministic scan phases: a phase only starts after the previous selected tools reach a terminal state.
- [x] Emit explicit phase `running`, `done`, and `skipped` events.
- [x] Ensure every selected tool ends as `done`, `error`, or `skipped` before scan completion.
- [x] Persist scan progress on the `Scan.progress` model so frontend refresh/reconnect does not lose state.
- [x] Replay persisted progress from `/api/scans/{scan_id}/progress` before streaming live events.
- [x] Stop frontend from treating an SSE/network error as scan completion.
- [x] Add frontend polling fallback to verify real scan status.
- [x] Write canonical unique subdomain hand-off files after subdomain enumeration:
  - `output/<domain>/subdomains_merged.txt`
  - `output/<domain>/subdomains.txt`
- [x] Filter merged hand-off files against out-of-scope patterns before downstream phases.
- [x] Create `alive_subdomains.txt` before HTTP/port tools start.
- [x] Create `alive_urls.txt` after HTTP probing and before URL crawler/vuln/screenshot tools need it.
- [x] Fix frontend result filters by making filter values Angular signals instead of plain fields hidden behind cached `computed()` values.
- [x] Reset pagination when filters change.
- [x] Fix tool availability for registry names that are not binaries, especially `dns_records` and `zone_transfer` which require `dig`.
- [x] Improve parser fallback for tools that write to `-o` files and may not emit stdout.
- [x] Fix the typo in the httpx follow-redirects flag.

## Files changed

- `backend/scan_engine.py`
- `backend/api/scans.py`
- `backend/api/tools.py`
- `backend/models/__init__.py`
- `backend/tools/base.py`
- `backend/tools/registry.py`
- `backend/tools/subdomain/crtsh.py`
- `backend/tools/subdomain/amass.py`
- `backend/tools/subdomain/subfinder.py`
- `backend/tools/subdomain/shuffledns.py`
- `backend/tools/dns/dns_records.py`
- `backend/tools/dns/dnsx.py`
- `backend/tools/dns/zone_transfer.py`
- `backend/tools/http/httpx_tool.py`
- `backend/tools/http/naabu.py`
- `backend/tools/urls/gau.py`
- `backend/tools/urls/katana.py`
- `backend/tools/vuln/nuclei.py`
- `frontend/src/app/core/models/index.ts`
- `frontend/src/app/features/scan/scan-progress.component.ts`
- `frontend/src/app/features/results/results.component.ts`
- `frontend/src/app/features/results/results.component.html`

## Verification performed

- [x] Python syntax compilation across every backend `.py` file.
- [x] Imported the registry and checked internal/binary availability logic.
- [x] Tested the subdomain merge helper with duplicate and out-of-scope hostnames.

## Recommended manual verification

- [ ] `cd docker && docker compose up --build`
- [ ] Create a project with one in-scope target and one OOS pattern.
- [ ] Launch a scan with at least `crtsh`, `subfinder`, `dnsx`, `httpx`, `waybackurls`, `katana`, `nuclei` selected.
- [ ] Confirm the progress page advances phase-by-phase and does not mark complete during transient SSE reconnects.
- [ ] Confirm `output/<domain>/subdomains_merged.txt` contains unique in-scope hosts before DNS starts.
- [ ] Confirm result filters work in Subdomains, HTTP, Vulns, and URLs tabs.

## Follow-up fixes from Docker rebuild log

- [x] Disabled Angular production font inlining so Docker builds do not fail when Google Fonts cannot be fetched.
- [x] Removed external Google Fonts links from `frontend/src/index.html`.
- [x] Removed external Chart.js CDN dependency and bundled Chart.js through the existing npm dependency.
- [x] Fixed typo'd CSS properties: `overflsg-*` → `overflow-*`.
- [x] Confirmed backend Python syntax compilation still passes.
- [ ] Re-run full `docker compose build --no-cache && docker compose up` locally with recon binaries/network access.

### Important Docker note

If `docker compose build --no-cache` fails and you then run `docker compose up`, Docker can still start the previous successfully built `shadow-grid:1.0.0` image. That is why logs may still show old commands such as `-follsg-redirects` even though the source code was patched. Rebuild must complete successfully before runtime logs can prove the new code is running.


## Validation pass v3
- [x] Confirmed Angular Docker production build no longer fails on Google Font inlining.
- [x] Added `netbase` so Debian slim provides service mappings required by `whois`.
- [x] Added `massdns` build/copy into the final image because `shuffledns` is only a wrapper around massdns.
- [x] Added dependency-aware tool availability checks. `shuffledns` now skips cleanly when `massdns` is missing.
- [x] Added non-interactive `asnmap` handling. It now skips cleanly unless `PDCP_API_KEY` is provided.
- [x] Added `PDCP_API_KEY` pass-through in docker-compose.
- [x] Added overall progress counters separate from per-phase counters.
- [x] Prevented hand-off artifacts from inflating frontend tool-completion totals.
- [x] Stripped ANSI color codes from CLI error messages before showing them in the UI.

## Validation pass v4
- [x] Fixed the `httpx` binary collision. ProjectDiscovery httpx is now staged as `pd-httpx`, and the tool runner calls `pd-httpx` directly.
- [x] Moved Go binary copy after `pip install` so Python console scripts cannot overwrite recon binaries during the Docker build.
- [x] Added API key settings persistence via `/api/settings/api-keys`.
- [x] Added Settings UI fields for ProjectDiscovery Cloud, GitHub, Shodan, Censys and Chaos keys.
- [x] Applied saved API keys to process environment on backend startup, tool-list requests and scan start.
- [x] Preserved existing saved secrets when password fields are left blank or returned masked.
- [x] Improved `alive_urls.txt` generation: httpx URLs first, naabu web-port fallback second, alive-subdomain http/https fallback last.
- [x] Added empty-input handling for `httpx`, `nuclei` and `gowitness` so empty files skip cleanly instead of producing confusing failures.
- [x] Added `gowitness` Chromium path detection and recursive screenshot discovery.
- [x] Added `nuclei` `-jsonl` support with fallback to legacy `-json`.
- [x] Re-ran backend Python syntax compilation successfully.
- [x] Unit-tested API key merge/masking/env application and alive URL fallback generation.
- [ ] Rebuild and run the Docker image locally to validate real `pd-httpx`, `nuclei`, and `gowitness` behavior with live network access.

## v5 Additions

- [x] Screenshot result cards now render the actual image preview.
- [x] Screenshot click opens a lightbox with a larger preview and full-image link.
- [x] Added safe `/api/results/{scan_id}/artifact` endpoint for screenshot/markdown artifacts.
- [x] Added `google_dorks` internal phase-6 tool that generates manual advanced Google dorks without scraping Google.
- [x] Added AI API key settings: OpenAI/ChatGPT, Anthropic/Claude, Google AI/Gemini, DeepSeek, and Groq.
- [x] Added `ai_analysis` internal tool gated by saved AI API keys.
- [x] AI Analysis runs last in phase 6 so it can consume all previous phase outputs plus dorks/screenshots/vuln output.
- [x] AI Analysis writes `ai_analysis.md`, `ai_analysis_prompt.md`, and `ai_analysis_context.json`.
- [x] Added AI Analysis tab for Markdown preview in the web app.
- [x] Added Dorks tab for generated Google dork preview/export.
- [x] Tool selection disables AI Analysis when no AI key is saved and shows a warning.
