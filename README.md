# Shadow-Grid v3

Full-stack recon automation framework — Docker + FastAPI + Angular.

## Quick Start

```bash
cd shadowgrid/docker
docker compose up --build
```

Open **http://localhost:8080** → Create project → Add targets → Launch scan.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  Browser (Angular 17)                   │
│  - Project management                   │
│  - Scan config + tool selection         │
│  - Live progress (SSE)                  │
│  - Results dashboard (8 tabs)           │
└────────────────┬────────────────────────┘
                 │ HTTP / SSE
┌────────────────▼────────────────────────┐
│  FastAPI Backend (Python 3.12)          │
│  - REST API for projects/scans/results  │
│  - Async parallel scan engine           │
│  - Tool abstraction layer               │
│  - Dual storage (file + Azure)          │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│  Storage Layer                          │
│  ├─ File Storage (always on)            │
│  │   output/<domain>/<tool>_output.txt  │
│  └─ Azure Table Storage (optional)      │
│      shadowgrid{Projects|Targets|Scans|   │
│               Results|Config}           │
└─────────────────────────────────────────┘
```

## Docker Commands

```bash
# Build and start
cd docker && docker compose up --build -d

# View logs
docker logs -f shadowgrid

# Stop
docker compose down

# Shell into container
docker exec -it shadowgrid bash
```

## CLI Usage (no Docker required)

```bash
cd shadowgrid
pip install -r backend/requirements.txt

# Full scan
python3 recon.py -d example.com

# Passive only
python3 recon.py -d example.com --passive-only

# Specific tools
python3 recon.py -d example.com --tools crtsh,subfinder,httpx,nuclei

# Multiple targets + OOS
python3 recon.py -d example.com shop.example.com --oos "*.internal.example.com"

# With Azure storage
python3 recon.py -d example.com --azure-conn "DefaultEndpointsProtocol=https;..."

# List all tools and availability
python3 recon.py -d x --list-tools
```

## Adding a New Tool

1. Create `backend/tools/<category>/mytool.py`
2. Subclass `BaseTool`, set `name`, `category`, `description`, `parallel_group`
3. Implement `run()` and `parse()`
4. Add one line to `backend/tools/registry.py`

That's it. No other files need changing.

## Azure Table Storage Setup

1. Create Azure Storage account
2. Open the web UI → Settings → Enable Azure Table Storage
3. Paste your connection string (or account name + key)
4. Tables are created automatically

Or via environment variables in docker-compose:
```env
AZURE_STORAGE_ENABLED=true
AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=...
```

## Scan Phases (parallel execution)

| Phase | Tools | Group |
|-------|-------|-------|
| 1 — Asset | whois, asnmap | parallel |
| 2 — Subdomain | crtsh, assetfinder, subfinder, amass, shuffledns | **all parallel** |
| 3 — DNS | dnsx, dns_records, zone_transfer | parallel |
| 4 — HTTP | httpx, naabu | parallel |
| 5 — URLs | waybackurls, gau, katana, urlfinder | **all parallel** |
| 6 — Vuln+SS | nuclei, gowitness, whatweb | parallel |

## Pre-installed Tools

| Tool | Purpose |
|------|---------|
| assetfinder | Passive subdomain discovery |
| subfinder | Multi-source passive subdomain enum |
| amass | OWASP passive subdomain enum |
| shuffledns | Active DNS bruteforce |
| crt.sh | Certificate transparency (HTTP) |
| dnsx | DNS resolution + record lookup |
| httpx | HTTP probing + tech detection |
| naabu | Port scanning (top 1000) |
| nuclei | Vulnerability scanning |
| gowitness | Web screenshots |
| whatweb | Technology fingerprinting |
| waybackurls | Historical URLs from Wayback Machine |
| gau | GetAllURLs (Wayback + CommonCrawl + OTX) |
| katana | Active web crawler |
| asnmap | ASN + IP range discovery |
| whois | WHOIS lookup |
| dig | DNS record queries |
