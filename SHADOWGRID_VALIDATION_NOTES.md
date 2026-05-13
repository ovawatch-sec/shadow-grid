# ShadowGrid Validation Notes — v3

## Issues confirmed from the runtime log

1. The Angular production build issue from v2 was fixed; the later log shows `frontend-build 6/6 RUN npm run build` completed successfully.
2. `whois` failed at runtime with `getaddrinfo(whois.registry.net.za): Servname not supported for ai_socktype`.
3. `asnmap` failed non-interactively with `Could not read input from terminal: open /dev/tty: no such device or address`.
4. `shuffledns` failed because `massdns` was missing, even though `shuffledns` itself was installed.

## Fixes added in v3

- Added `netbase` to the final Debian image so service mappings required by `whois` exist in the slim container.
- Built and copied `massdns` into `/usr/local/bin` because `shuffledns` depends on it.
- Added dependency-aware availability checks:
  - `shuffledns` now requires both `shuffledns` and `massdns`.
  - `asnmap` now requires `PDCP_API_KEY` before it runs.
- Added `PDCP_API_KEY` passthrough in `docker/docker-compose.yml`.
- Added a startup warning when `asnmap` exists but `PDCP_API_KEY` is empty.
- Switched `asnmap` execution to non-interactive flags: `asnmap -domain <domain> -silent -duc`.
- Added ANSI stripping for CLI errors before displaying them in the frontend.
- Added backend overall progress counters separately from phase counters.
- Updated the frontend progress component to use backend overall counters instead of guessing totals from visible rows.
- Excluded hand-off artifacts such as `subdomain-merge`, `alive-subdomains`, and `alive-urls` from fallback tool-completion counts.

## Validation performed in this environment

- Backend Python syntax compilation passed for all backend Python files.
- Availability logic was tested with mocked binaries:
  - `asnmap` skips cleanly when `PDCP_API_KEY` is missing.
  - `asnmap` is available when the binary and `PDCP_API_KEY` exist.
  - `shuffledns` is available only when both `shuffledns` and `massdns` exist.
- ANSI cleanup was tested against ProjectDiscovery-style colored errors.
- Subdomain merge was tested for:
  - deduplication
  - root-domain enforcement
  - wildcard stripping
  - out-of-scope filtering
  - writing both `subdomains_merged.txt` and `subdomains.txt`
- Phase orchestration was tested with fake tools:
  - phase 2 started only after phase 1 emitted its terminal phase event
  - overall counters ended at `3 / 3`
  - final scan event was `completed`

## Not fully validated here

A full Docker build and live recon scan were not completed in this environment because the available execution window is shorter than the Docker/npm/go build time for this project. The user's Docker log already showed the Angular build completing after the v2 font fix, and v3 only adds targeted Docker/runtime dependency fixes plus backend/frontend progress logic.

## v5 Validation Notes

Commands run in this environment:

```bash
PYTHONPATH=backend python3 -m compileall -q backend
PYTHONPATH=backend python3 - <<'PY'
from pathlib import Path
from tools.registry import REGISTRY, get_tool
assert 'google_dorks' in REGISTRY
assert 'ai_analysis' in REGISTRY
assert get_tool('google_dorks', Path('/tmp/out'), Path('/tmp/data')).availability_error() is None
assert 'AI API key' in get_tool('ai_analysis', Path('/tmp/out'), Path('/tmp/data')).availability_error()
PY
PYTHONPATH=backend OPENAI_API_KEY=test python3 - <<'PY'
from pathlib import Path
from tools.registry import get_tool
assert get_tool('ai_analysis', Path('/tmp/out'), Path('/tmp/data')).availability_error() is None
PY
```

Also validated:

- Tool API key merge keeps existing masked/blank secrets instead of wiping them.
- Google dork tool writes `google_dorks.md` and returns dork rows from a dummy `subdomains_merged.txt`.
- Backend artifact serving path is constrained under `settings.output_dir` to block traversal.

Not validated here:

- Full Docker build/live recon scan. The project build takes several minutes and requires the external toolchain/network available in your Docker environment.
- Real AI provider API calls. The tool has fallback Markdown output if the provider call fails.
