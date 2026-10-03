<div align="center">

<img src="frontend/src/assets/shadow-grid-icon.png" width="132" alt="ShadowGrid logo">

# ShadowGrid

**An application-security platform — map, assess, and track the security posture of every app you own.**

![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Angular](https://img.shields.io/badge/Frontend-Angular%2017-DD0031?logo=angular&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tools](https://img.shields.io/badge/security%20tools-20%2B-00e884)

</div>

---

## Overview

**ShadowGrid** is a full-stack **application-security (AppSec) platform**. It turns 20+ best-in-class open-source security tools into a single, phased, parallelised assessment pipeline behind a modern SaaS-style web app — with a posture dashboard, cross-program scan activity, and a unified findings view.

You organise work into **programs** (an application and its in-scope / out-of-scope scope), then launch **assessments** against them. Each assessment walks seven deterministic phases — asset discovery, subdomain enumeration, DNS resolution, HTTP probing & port scanning, URL discovery, API & parameter analysis, and vulnerability scanning / WordPress / screenshots / dorking / AI analysis — running independent tools in parallel, streaming **live progress over SSE**, and collecting every finding into one dashboard.

The pipeline does not stop at a URL list. Phase 6 collapses discovered URLs into
endpoint patterns with their parameter sets, reads any OpenAPI specification or
introspectable GraphQL schema the target exposes, and hands phase 7 — and you, in
Burp or Caido — a deduplicated **parameter-level** test surface. Payload-sending
tools exist (`nuclei_dast`, `vhost`) but are strictly opt-in.

It's built for **security teams, penetration testers, and bug-bounty hunters** who want repeatable, resumable, trackable AppSec assessments without hand-wiring a dozen CLIs and reconciling their output by hand. (Attack-surface / asset enumeration is one phase of the pipeline — not the whole product.)

> The name says what it does: a **grid** of security probes mapping an application's exposure — everything sits in **shadow** until an assessment lights it up, with a live reticle locked on the host being probed (exactly what the logo depicts).

### Why ShadowGrid

- **A platform, not a script** — a posture **Dashboard**, global **Assets**,
  **Findings**, and **Changes**, plus cross-program **Assessments** in a light/dark SaaS UI.
- **One pipeline, many tools** — subfinder, amass, httpx, naabu, nuclei, katana, wpscan, gowitness and more, coordinated so each phase hands clean artifacts to the next.
- **Phase gating** — a phase never starts until the previous one has fully drained and written its hand-off files (e.g. merged subdomains → alive hosts → alive URLs), so downstream tools always get real input.
- **Validated data** — discovered URLs are re-probed and dead links dropped before they reach results; WordPress scanning is driven off the validated alive-URL set.
- **Live & interactive** — watch every tool report in real time (grouped per domain, not stacked), and **browse, filter and sort the results table while the assessment is still running**.
- **Resumable & cancellable** — stop a run mid-flight (in-flight processes are terminated **and the cancelled assessment's data is deleted**), or resume a program and reuse prior successful results instead of re-running finished work.
- **Editable & tidy** — rename a program or edit its description after creation, and **clear all of a program's assessment history** (including cancelled runs) in one click.
- **Scope-aware** — out-of-scope patterns (incl. wildcards) are filtered at every stage, so results stay inside your authorisation.
- **Assessment request identity** — every assessment uses `ShadowGrid/3.1` by
  default and can define a custom User-Agent plus validated headers for
  authenticated target testing. Header values are redacted from logs and manifests,
  and credential-bearing headers are **bound to an explicit host allowlist** so a
  session token is never sprayed across discovered hosts.
- **SQL-first persistence** — mandatory local SQLite storage with transactions,
  foreign keys, WAL concurrency, and automatic migration from legacy JSON metadata.
- **Continuous monitoring** — durable daily, weekly, or monthly schedules,
  inventory drift, deduplicated webhook notifications, and failed-tool retries.
- **Finding workflow** — triage dispositions, assignees/tags/notes APIs,
  suppression rules, severity overrides, and automatic reopening on recurrence.
- **Portable reporting** — HTML/print-to-PDF, Markdown, CSV, JSON, and SARIF
  exports plus a relationship graph backed by the normalized SQL inventory.
- **Role-based access** — administrator and analyst accounts plus read-only
  viewers; existing installations are migrated to the `admin` account.

---

## Quick Start (Docker)

```bash
git clone https://github.com/ovawatch-sec/shadow-grid.git
cd shadow-grid

docker compose -f docker/docker-compose.yml up --build -d
```

Open **http://localhost:8080**, then:

1. **Set a password** (required on first visit) and log in.
2. Land on the **Dashboard** (security posture across all programs).
3. **Create a program** and define its **scope** (in-scope apps + any out-of-scope patterns).
4. **Select tools** and **launch an assessment** — watch grouped live progress, browse results as they stream in, then review the full findings dashboard.

---

## Web interface

A modern, SaaS-style single-page app with a light/dark theme toggle (it follows your OS preference until you choose):

- **Dashboard** — security-posture overview: programs, active assessments, completed assessments, and a recent-activity feed.
- **Programs** — create/manage application-security programs; each card shows its assessment count. Inside a program you can **edit its name/description**, define **scope**, launch a **new assessment**, review the **assessments** history, and **clear all program data** (a guarded action that removes every assessment — including cancelled ones — and their results, while keeping the program and its scope).
- **Assets** — a normalized inventory across every program. Select an asset to
  inspect its states, observations, relationships, findings, and originating evidence.
- **Findings** — a severity-prioritized portfolio queue linked to affected assets,
  programs, and assessment evidence.
- **Changes** — cross-program drift showing new, removed, and changed assets
  alongside new and resolved findings.
- **Assessments** — a cross-program board of running and recent assessments as clean status cards, so scanning many domains at once stays readable instead of stacking into one long list.
- **Live progress** — per-assessment view that groups tools into a card **per domain**, each with its own progress bar; cancel from here, or jump straight to the results collected **so far**.
- **Results** — an asset-centric workspace organized into Overview, Assets,
  Findings, Changes, Evidence, and Assessment. Raw DNS, HTTP, URL, WordPress,
  screenshot, technology, dork, and AI records remain in the Evidence explorer.

---

### Normalized inventory and change tracking

Every completed assessment now correlates raw tool output into stable assets,
observations, relationships, and findings. The **Assets** and **Changes** results
tab shows the current attack surface and compares it with the preceding completed
assessment. The same data is available from:

- `GET /api/inventory/{scan-id}`
- `GET /api/inventory/{scan-id}/delta`

Assets are typed: `domain`, `hostname`, `ip_address`, `url`, **`endpoint`**,
**`parameter`**, `service`, `technology`, and `email`. An endpoint is stored as
`METHOD url` with its parameter set, risk hints, and declared auth requirement,
and relates to the parameters it accepts (`accepts_parameter`), the host serving
it (`served_by`), and the concrete URLs observed for it (`instance_of`). That is
what lets a finding hang off `POST /api/orders` rather than off a bare hostname.

### Handing off to manual testing

Recon ends where manual testing starts, so the discovered surface exports in
formats those tools import directly:

| Format | Endpoint | Use |
|--------|----------|-----|
| `targets` | `GET /api/reports/{scan-id}/export?format=targets` | Plain URL list for Burp, Caido, or ZAP |
| `har` | `GET /api/reports/{scan-id}/export?format=har` | HAR 1.2 of every URL and documented endpoint, with method and query string, for replay tooling |

Both are also buttons on the results page, alongside HTML / Markdown / CSV /
JSON / SARIF. HAR responses are intentionally empty: these are requests to
replay, not captured traffic.

Each completed scan also writes a hashed `_manifest.json` beside its evidence.
Container readiness is exposed at `GET /api/ready`; authenticated request metrics
are available in Prometheus text format at `GET /api/metrics`. All of these
features are local and require no commercial account or subscription.

### Authenticated scanning and credential scoping

Most real AppSec bugs live behind a login, so an assessment can carry
`Authorization`, `Cookie`, `X-API-Key`, or any custom header. Those headers are
treated differently from the rest:

- A header is classified as **credential-bearing** when its name is a known
  identity header or contains `auth`, `token`, `session`, `cookie`, `secret`,
  `credential`, or `api-key` — so `X-Acme-Session` is caught too.
- Credential headers are sent **only** to hosts listed in the assessment's
  **Credential hosts** field (exact names or `*.example.com` wildcards).
- **An empty allowlist means they are never sent.** Credentials are opt-in per
  target, never implied by scope membership.
- A raw IP is matched only exactly, so `origin_exposure`'s direct-IP probes
  cannot inherit a hostname's session.
- A tool that cannot name its targets gets broadcast-safe headers only. When a
  list-driven binary (nuclei, katana, httpx) is handed any host outside the
  allowlist, credentials are withheld from that run and the assessment reports
  it in progress — a degraded authenticated run is never silent.

Why it matters: without this, a 200-subdomain authenticated scan hands a live
session token to all 200 hosts — including one that `subdomain_takeover` has
just flagged as claimable by somebody else.

Set it in the web UI next to the custom headers, or via the API:

```jsonc
POST /api/scans/
{
  "project_id": "…",
  "tools": ["httpx", "katana", "param_miner"],
  "custom_headers": { "Cookie": "session=…" },
  "credential_hosts": ["app.example.com", "*.staging.example.com"]
}
```

Schedules carry the same field, so a recurring authenticated assessment keeps
its scoping.

### Accessing ShadowGrid from a VM host

When Docker runs inside a VM, open `http://<vm-ip>:8080` from the host. Compose
binds port 8080 on all VM interfaces by default. Use
`SHADOWGRID_BIND_ADDRESS=127.0.0.1` if you intentionally want VM-local access
only. For an internet-facing deployment, set `CORS_ORIGINS` to an explicit,
comma-separated origin allowlist and place TLS authentication or a private VPN
in front of ShadowGrid.

## First Run & Authentication

ShadowGrid uses single-password auth — no default credentials ever exist. On first visit the UI forces you to set a password; every project, scan, and settings page is locked behind login. Tokens are HMAC-signed and expire after 7 days.

**Forgot the password?** Reset it offline with the bundled script (it lives in the same Docker volume as the app data):

```bash
# Interactive prompt inside the running container
docker exec -it shadowgrid python3 /app/backend/reset_password.py

# …or via the convenience wrapper
./docker/reset-password.sh
```

By default the reset rotates the token-signing secret (logging out all sessions). Pass `--keep-sessions` to preserve existing logins. See `--help` for all options.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  Browser (Angular 17, light/dark SaaS)   │
│  - Posture dashboard + scan activity     │
│  - Program / scope management + editing  │
│  - Assessment config + tool selection    │
│  - Live progress (SSE), grouped by domain│
│  - Interactive results (live while running)│
└────────────────┬─────────────────────────┘
                 │ HTTP / SSE   (nginx reverse proxy)
┌────────────────▼─────────────────────────┐
│  FastAPI Backend (Python 3.12)           │
│  - REST API: projects / scans / results  │
│      · PATCH project (edit details)      │
│      · POST project/clear (wipe history) │
│  - Async phased + parallel scan engine   │
│  - Pluggable tool abstraction layer      │
│  - Single-password auth (bearer tokens)  │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│  Storage Layer                           │
│  ├─ SQLite: data/database/shadowgrid.db  │
│  │    projects, targets, scans, results, │
│  │    inventory, auth, configuration     │
│  └─ Evidence filesystem                 │
│       projects/<project>/scans/<scan>/  │
│         assets/<domain>/<tool artifacts>│
└──────────────────────────────────────────┘
```

The whole stack ships as a **single container** — Angular build, FastAPI backend, ~20 compiled Go/Ruby recon binaries, and nginx — built via a multi-stage Dockerfile.

---

## Scan Phases (parallel execution)

| Phase | Tools | Execution |
|-------|-------|-----------|
| 1 — Asset Discovery | `whois`, `asnmap`, optional `shodan`, optional `email_finder` | parallel |
| 2 — Subdomain Enumeration | `crtsh`, `assetfinder`, `subfinder`, `amass`, `shuffledns` | **all parallel** |
| 3 — DNS Resolution | `dnsx`, `dns_records`, `zone_transfer` | parallel |
| 4 — HTTP, TLS & Port Validation | `httpx`, `tlsx`, `naabu` | parallel |
| 5 — URL Discovery | `waybackurls`, `gau`, `katana`, `urlfinder`, opt-in `ffuf`, opt-in `vhost` | **all parallel** (URLs are re-probed; dead links dropped) |
| 6 — API & Parameter Analysis | `api_spec`, `param_miner` | parallel |
| 7 — Vuln · CVE · Takeover · WordPress · Screenshots · Dorks · AI | `nuclei`, `cve_check`, `subdomain_takeover`, `wpscan`, `gowitness`, `whatweb`, `google_dorks`, opt-in `nuclei_dast`, `ai_analysis` | parallel (AI runs last) |

Between phases, ShadowGrid writes canonical hand-off artifacts — `subdomains_merged.txt` → `resolved_subdomains.txt` / `probe_candidates.txt` → `alive_urls.txt` → `params.txt` / `urls_deduped.txt` / `api_endpoints.txt`. Unresolved fallback candidates are never presented as alive; HTTP/TLS tools validate candidates and record explicit reachability states.

Phase 6 is where enumeration becomes AppSec. URL discovery produces tens of
thousands of near-identical links; nothing can test that directly. `param_miner`
collapses them into endpoint patterns (`/order/8821` and `/order/9142` are one
route), groups by parameter set, and keeps one concrete representative each.
`api_spec` looks for the specification that describes the whole surface at once.
What comes out is a parameter list — the input DAST, and a human with Burp or
Caido, actually need.

**Notes**
- **Cancel deletes data:** every assessment owns an isolated `projects/<project-id>/scans/<scan-id>/assets/` workspace. Cancelling kills in-flight processes and deletes that assessment's results, progress, and artifacts without affecting another run.
- **Raw-output cleanup:** the filesystem workspace is transient ingestion storage. Screenshots are persisted as deduplicated SQLite BLOBs and all parsed evidence is stored in database records before a completed, failed, or cancelled assessment can remove its isolated raw workspace. The assessment, results, inventory, relationships, findings, and screenshot gallery remain available; active assessments are protected from cleanup.
- **Clear program data:** from a program's page you can wipe **all** of its assessment history — every run including cancelled ones, and their results — while keeping the program and its scope. Any still-running assessment is terminated first.
- **Edit program details:** a program's name and description can be changed at any time after creation (`PATCH /api/projects/{id}`).
- **Resume vs. fresh:** reuse is permitted only from one completed assessment with the same scope, exclusions, selected tools, and wordlist fingerprint. Its evidence snapshot is copied into the new workspace before results are reused.
- **URL validation** — every discovered URL (waybackurls, gau, katana, urlfinder) is re-probed with httpx and any that no longer respond (dead hosts, `404`/`410` gone pages) are removed before it reaches the results. Broken/blank screenshots are likewise discarded.
- **WordPress scanning** — `wpscan` checks **every verified alive HTTP service**, even when technology fingerprinting does not identify WordPress. URLs are normalised to their `scheme://host:port` site root and de-duplicated, with no fixed target cap. WPScan's `--force` mode safely evaluates each service and surfaces any core/plugin/theme vulnerabilities, interesting findings, and enumerated users in a dedicated **WordPress** results tab. Add a **WPScan API token** in Settings to query the WordPress Vulnerability Database for CVE-level results.
- **Google dorking** executes generated dorks live through SerpApi's Google Search API when a SerpApi key is saved in Settings, otherwise it uses the no-key DuckDuckGo fallback.
- **Subdomain takeover** hunts dangling/claimable subdomains (nuclei takeover templates, plus `subzy` when available).
- **CVE checks** run Nuclei's CVE-tagged templates only against URLs already
  verified as alive. General Nuclei scanning excludes that tag to prevent the
  dedicated CVE pass from producing duplicate findings.
- **Shodan enrichment** is opt-in per assessment. It runs only when selected and
  a Shodan API key is saved in Settings, performs one scoped hostname search per
  root domain, rejects out-of-scope hostnames, and correlates returned services,
  CPEs, IPs, and reported CVEs. Filtered Shodan searches may consume API credits.
- **Email discovery** is opt-in per assessment and requires a Hunter API key in
  Settings. It performs a scoped Domain Search for up to 10 addresses per root
  domain. Email Verifier calls are controlled by a separate assessment checkbox
  because each discovered address may consume an additional verification credit.
- **AI analysis** ranks the assessment when an AI provider key (OpenAI / Anthropic / Google / DeepSeek / Groq) is configured in Settings, producing a **separate analysis per in-scope asset**. The prompt is grounded rather than open-ended: every claim must cite the artifact it came from (`[params]`, `[nuclei]`, `[web_posture]`), hostnames/versions/CVE identifiers must be copied from the context rather than recalled, inference is labelled as such, and a section with no supporting evidence must say so instead of padding. It is fed the deduplicated parameter and API surface first — artifacts are sampled top-down against a fixed character budget — and each artifact carries its real row count, so the model can report what it was **not** shown. Output is a verdict, a ranked test surface, attack paths with confirm/refute conditions, and the gaps in the assessment itself (which tool did not run, and what to run next).
- **Parameter mining** (`param_miner`) runs offline over the URL phase's output — no requests, no API key. Path segments that look like identifiers (numeric, UUID, hash, date, slug) collapse to `{id}`, so one route is one endpoint however many ids were crawled. It writes `params.txt` (fuzzable URLs), `urls_deduped.txt` (one representative per endpoint), and `param_names.txt`, and tags each endpoint with the bug classes its parameter names suggest (`ssrf_or_redirect`, `path_traversal`, `sql_injection`, `reflected_xss`, `command_injection`, `template_injection`, `access_control`).
- **API discovery** (`api_spec`) probes conventional OpenAPI/Swagger locations and GraphQL entry points on every verified service. A readable specification is flattened into endpoints with their methods, query/path/body parameters, and declared auth requirements; an answering introspection query is reported as a **medium** finding. One specification maps more surface than thousands of content-discovery requests.
- **Active testing is opt-in.** `nuclei_dast` (parameter fuzzing for XSS, SQLi, SSTI, SSRF, LFI, and open redirect) and `vhost` (Host-header fuzzing against verified service IPs) **send attack payloads**. They are excluded from every default selection, must be named explicitly, and warn before they start. `nuclei_dast` needs `params.txt`, so run `param_miner` first; it is rate-limited to 20 req/s and requires nuclei v3.2+.

---

## Pre-installed Tools

| Tool | Purpose |
|------|---------|
| assetfinder | Passive subdomain discovery |
| subfinder | Multi-source passive subdomain enumeration |
| amass | OWASP passive subdomain enumeration |
| shuffledns | Active DNS bruteforce (via massdns) |
| crt.sh | Certificate-transparency lookup (HTTP) |
| dnsx | DNS resolution + record lookups |
| httpx | HTTP probing + tech detection |
| tlsx | TLS and certificate inventory, including SAN relationships |
| naabu | Port scanning |
| nuclei | Template-based vulnerability scanning |
| cve_check | CVE-tagged Nuclei checks against verified alive URLs |
| ffuf | Opt-in bounded content discovery against alive services (with `.bak`/`.old`/`.zip`/`.sql` variants) |
| param_miner | Endpoint/parameter extraction and URL pattern dedup (offline, no binary) |
| api_spec | OpenAPI/Swagger discovery and GraphQL introspection checks |
| nuclei_dast | **Active** parameter fuzzing via nuclei DAST templates (opt-in) |
| vhost | **Active** virtual-host discovery via Host-header fuzzing (opt-in) |
| wafw00f | WAF and reverse-proxy fingerprinting |
| web_posture | Native security header, cookie, and CORS posture checks |
| secret_exposure | Masked secret-exposure detection — 23 provider patterns plus entropy scoring, JavaScript and config files first |
| origin_exposure | Direct-origin reachability and response-correlation checks |
| shodan | Optional Shodan service and reported-CVE enrichment |
| email_finder | Hunter domain email discovery with optional deliverability verification |
| subzy | Subdomain-takeover detection (secondary engine) |
| wpscan | WordPress vulnerability checks across every verified alive HTTP service |
| gowitness | Web screenshots |
| whatweb | Technology fingerprinting |
| waybackurls | Historical URLs from the Wayback Machine |
| gau | GetAllURLs (Wayback + CommonCrawl + OTX) |
| katana | Active web crawler |
| urlfinder | Passive URL discovery |
| asnmap | ASN + IP-range discovery |
| whois | WHOIS lookups |
| dig | DNS record queries |

> A tool that isn't installed (or is missing an API key) is cleanly **skipped** and reported in progress — it never breaks a scan.

---

## CLI Usage (no Docker required)

```bash
cd shadow-grid
pip install -r backend/requirements.txt

# Full scan
python3 recon.py -d example.com

# Passive only
python3 recon.py -d example.com --passive-only

# Specific tools
python3 recon.py -d example.com --tools crtsh,subfinder,httpx,nuclei

# Active testing — never included in a default run, must be named explicitly
python3 recon.py -d example.com --tools katana,gau,param_miner,nuclei_dast

# Multiple targets + out-of-scope patterns
python3 recon.py -d example.com shop.example.com --oos "*.internal.example.com"

# Custom output / data directories
python3 recon.py -d example.com --output-dir ./output --data-dir ./data

# List all tools, with the exact reason any of them is unavailable
python3 recon.py --list-tools
```

> The CLI shares the exact same scan engine and tool layer as the web app — only the entry point differs.

A bare `python3 recon.py -d example.com` runs every tool **except** the
active-testing ones (`nuclei_dast`, `vhost`). Those send attack payloads, so
they only run when named in `--tools`, and the CLI prints an authorisation
warning before starting them.

### API keys for the CLI (`.env`)

The web UI stores API keys in Settings and Docker passes them as container
environment variables. The CLI has neither, so it reads a local credential
file:

```bash
cp .env.example .env
chmod 600 .env          # real credentials — .gitignore already excludes it
$EDITOR .env            # fill in only the keys you have

# Confirm what got loaded (values are masked, never printed)
python3 recon.py --show-config
```

`.env.example` documents every supported variable, which tool consumes it, and
what happens without it. Blank entries are ignored, so an unfilled placeholder
never shadows a real environment variable.

**Where the file is looked up** — first match wins:

| Order | Location |
|---|---|
| 1 | `--env-file /path/to/file` |
| 2 | `$SHADOWGRID_ENV_FILE` |
| 3 | `./.env` (current directory) |
| 4 | `<repo root>/.env` |
| 5 | `~/.config/shadowgrid/.env` |

A path given through `--env-file` or `$SHADOWGRID_ENV_FILE` must exist — a typo
is an error, not a silent fallback.

**Precedence** — highest first:

1. Variables already exported in your shell —
   `SHODAN_API_KEY=xxx python3 recon.py -d example.com` overrides the file for
   one run
2. The credential file
3. Keys saved in the database through the Settings UI

Use `--no-env-file` to ignore credential files entirely and run off the current
environment. The same file is also read when the API is started directly
(`cd backend && python3 -m uvicorn main:app`); under Docker, keep using
Settings or `docker-compose.yml`.

---

## Docker Commands

```bash
# Build & start (detached)
docker compose -f docker/docker-compose.yml up --build -d

# Follow logs
docker logs -f shadowgrid

# Shell into the container
docker exec -it shadowgrid bash

# Stop
docker compose -f docker/docker-compose.yml down
```

---

## SQL Storage

SQLite is the mandatory primary store and requires no external service or paid
account. The database is `data/database/shadowgrid.db` and uses WAL mode, foreign keys,
transactional upserts, and cascade deletes. On the first SQL-backed startup,
ShadowGrid imports existing projects, targets, scans, results, inventories,
authentication, and tool keys from `output/.meta/`. The legacy JSON tree is left
untouched as a recovery copy but is no longer read after migration.
Existing `output/shadowgrid.db` installations are copied automatically into the
durable data volume on first startup. The output volume then contains transient
tool workspaces only and can be cleaned without deleting authoritative records.

---

## Adding a New Tool

ShadowGrid's tool layer is pluggable — adding a tool touches two files:

1. Create `backend/tools/<category>/mytool.py`.
2. Subclass `BaseTool`; set `name`, `category`, `description`, `parallel_group`.
3. Implement `run()` (invoke the binary) and `parse()` (raw output → `list[dict]`).
4. Add one line to `backend/tools/registry.py`.
5. If the tool sends attack payloads, set `opt_in = True` so it is excluded from
   every default selection and only runs when named explicitly.

Rows returned by `parse()` are normalised into inventory assets by key: `host`,
`url`, `ip`/`a`, `port`, `tech`, `email`, and — for AppSec tools — `endpoint`
with `method` and `params`. A tool that makes its own HTTP requests should use
`self._headers_for_host(host)` so credential scoping is respected; one driving a
binary over a list should pass `hosts=` to `self._header_args()`.

That's it — the scan engine, API, and UI pick it up automatically.

---

## Project Structure

```
shadow-grid/
├── backend/            FastAPI app, scan engine, tool layer, storage, auth
│   ├── scan_engine.py      phased + parallel orchestration
│   ├── request_config.py   header validation + credential host binding
│   ├── env_file.py         local .env credential loading for CLI/bare runs
│   ├── inventory.py        assets, endpoints, parameters, findings, deltas
│   ├── tools/              one module per security tool (+ registry.py)
│   ├── storage/            mandatory SQLite persistence
│   ├── tests/              pytest suite (156 tests, no network or binaries needed)
│   └── reset_password.py   offline password-reset utility
├── frontend/           Angular 17 SPA — dashboard, programs, scan activity,
│                       live progress, interactive results (light/dark)
├── docker/             Dockerfile, docker-compose.yml, nginx.conf, entrypoint.sh
├── data/               wordlists, resolvers and other tool data
├── .env.example        credential template for CLI runs (copy to .env)
└── recon.py            CLI entry point (same engine as the web app)
```

---

## Development & Tests

```bash
# Backend — unit tests (no network / recon binaries required)
cd backend
pip install -r requirements.txt pytest
python -m pytest tests/ -q

# Frontend — type-check + production build
cd frontend
npm ci
npx ng build
```

The backend test suite (156 tests) covers the pure logic behind the assessment
lifecycle: URL liveness validation, wpscan target selection (including the
alive-URL signal), scan/result deletion, and the project update/clear endpoints,
plus the AppSec pipeline — credential-header scoping, endpoint/parameter
extraction, OpenAPI and GraphQL parsing, active-tool gating, secret detection
and entropy scoring, inventory endpoint modelling, and the Burp/Caido exports.
Everything runs offline: no network, no recon binaries, no API keys.

---

## Legal & Ethical Use

ShadowGrid is intended for **authorised security testing only** — your own assets, or targets you have explicit written permission to assess (e.g. an in-scope bug-bounty program or a signed engagement). Active modules (port scanning, DNS bruteforce, crawling, vulnerability templates) generate real traffic against targets. Scanning systems without authorisation may be illegal. **You are responsible for how you use this tool.**
