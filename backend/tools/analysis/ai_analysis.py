"""AI-assisted recon analysis.

Runs after normal phase-6 tools. It creates a compact prompt/context from all
phase artifacts, calls the first configured AI provider, and writes a Markdown
analysis that the web app can preview.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tool_secrets import has_any_ai_api_key
from tools.base import BaseTool, RunResult, clean_tool_output

MAX_ROWS_PER_FILE = 80
MAX_CHARS_PER_FILE = 18_000

#: What each artifact key means, given to the model so it can cite evidence by
#: name instead of describing where something "probably" came from.
ARTIFACT_LEGEND = """  params           deduplicated parameterised URLs — the primary test surface
  param_names      every distinct parameter name observed, most frequent first
  param_endpoints  endpoint patterns with their parameter sets and risk_hints
                   (risk_hints are name-based suspicions, never confirmations)
  api_endpoints    routes read from an OpenAPI/Swagger spec or GraphQL schema
  api_spec         the specification findings themselves, incl. exposed specs
  alive_urls       services verified as responding
  httpx            per-service status, title, detected technology
  tlsx             TLS certificate detail, including SANs
  naabu            open TCP ports
  subdomains       every name discovered, resolved or not
  dnsx             DNS resolution results
  nuclei           template-match findings
  nuclei_dast      active parameter-fuzzing findings (only if actively tested)
  cve_check        CVE-tagged template findings
  web_posture      security header, cookie flag, CORS and HTTP method posture
  secret_exposure  masked credential exposures (values are fingerprinted only)
  origin_exposure  direct-origin reachability behind a proxy or CDN
  takeover         dangling or claimable subdomain findings
  wpscan           WordPress core, plugin, theme and user findings
  whatweb          technology fingerprints
  vhost            virtual hosts found by Host-header fuzzing
  urls_deduped     one representative URL per discovered endpoint
  gau / wayback    historical URLs (noisy, heavily truncated)
  google_dorks     generated search queries and any live results"""

GENERIC_AI_PROMPT = """You are a senior application-security analyst triaging one target's recon
output. Your reader is a penetration tester who will act on this in Burp or
Caido within the next few minutes. They know what SSRF and IDOR are; do not
explain bug classes, tell them where to point.

# Input

A JSON object of ShadowGrid artifacts for a single domain. Every artifact has:
  file    the filename it came from
  exists  false when that tool did not run or produced nothing
  total   how many rows the file actually holds
  sample  a TRUNCATED subset of those rows

`total` larger than the sample means you are seeing part of the data. Never
state a count you cannot read from `total`, and never imply the sample is
complete.

Artifact meanings:
{legend}

# Grounding rules — these override every other instruction

1. End every factual claim with the artifact it came from, in brackets:
   `[nuclei]`, `[params]`, `[web_posture]`. A claim you cannot cite is a claim
   you must not make.
2. Copy hostnames, paths, parameters, versions and CVE identifiers verbatim
   from the context. Never reconstruct one from memory, never complete a
   partial one, and never name a CVE that is not already in the context.
3. Keep observation and inference apart. Prefix anything you concluded rather
   than read with `Inferred:` and name the observation it rests on.
4. Where the evidence does not support a section, write
   `No supporting evidence in this assessment.` and move on. A short accurate
   report is worth more than a padded one, and padding costs the reader trust.
5. Do not restate the input. The reader has the artifact files; they need your
   ranking and reasoning, not their data echoed back.
6. Recommend only non-destructive checks against the target in scope. No
   denial of service, no data destruction, no credential brute force, no
   automated exploitation, nothing aimed at third-party hosts.
7. A risk_hint, a parameter name, or a technology fingerprint is a reason to
   look — never evidence that a vulnerability exists. Say which it is.

# Output

Markdown only, no preamble, no closing summary, under 700 words total. Use
exactly these sections and respect each cap.

# ShadowGrid AI Analysis — <domain>

## Verdict
2-4 bullets. Where the real risk concentrates and what to open first. If the
assessment found little, say that plainly in one bullet.

## Priority Test Surface
A table, at most 10 rows, ordered by expected value. Parameterised endpoints
and documented API routes outrank bare hostnames; a host with no observed
functionality ranks last or is omitted.

| # | Target | Why it stands out | Evidence | First check |

`Target` is a method plus URL where you have one, otherwise a host.
`First check` is one specific action, not a methodology.

## Attack Paths
At most 4, strongest first. Each as:

**<short name>** — Target: `<target>` · Confidence: observed | inferred
- Hypothesis: one sentence.
- Evidence: cited facts that make this plausible.
- First request: the single concrete request or action to try.
- Confirms: the response that would prove it.
- Refutes: the response that kills it — stop there and move on.

## Gaps In This Assessment
At most 4 bullets. Which artifacts are missing or empty (`exists: false`),
what that blinds the reader to, and the single highest-value tool or action to
run next. Call out when no parameters were mined, when no API spec was found,
and when nothing was actively tested.

## Noise
At most 5 bullets. What looks interesting here but is not worth time, and the
one-line reason. Omit the section if everything in scope is worth looking at.""".replace(
    "{legend}", ARTIFACT_LEGEND,
)

#: Per-row and whole-context ceilings. The context is the expensive part of
#: every AI call, so it is bounded deterministically rather than by hope.
MAX_ROW_CHARS = 300
MAX_CONTEXT_CHARS = 45_000

#: (context key, filename, row cap), highest evidential value first. The
#: budget is spent from the top, so a thin assessment still sends what matters.
ARTIFACT_SOURCES: tuple[tuple[str, str, int], ...] = (
    ("params", "params.txt", 120),
    ("param_names", "param_names.txt", 100),
    ("param_endpoints", "param_miner.json", 60),
    ("api_endpoints", "api_endpoints.txt", 80),
    ("api_spec", "api_spec.json", 30),
    ("nuclei", "nuclei_results.jsonl", 50),
    ("nuclei_dast", "nuclei_dast.jsonl", 40),
    ("cve_check", "cve_results.jsonl", 40),
    ("secret_exposure", "secret_exposure.json", 40),
    ("web_posture", "web_posture.json", 40),
    ("takeover", "takeover_nuclei.jsonl", 20),
    ("origin_exposure", "origin_exposure.json", 20),
    ("wpscan", "wpscan.txt", 30),
    ("vhost", "vhost_results.json", 20),
    ("alive_urls", "alive_urls.txt", 80),
    ("httpx", "httpx.jsonl", 50),
    ("whatweb", "whatweb.jsonl", 30),
    ("tlsx", "tlsx.jsonl", 20),
    ("naabu", "naabu.txt", 30),
    ("subdomains", "subdomains_merged.txt", 60),
    ("dnsx", "dnsx.txt", 40),
    ("urls_deduped", "urls_deduped.txt", 60),
    ("katana", "katana.txt", 30),
    ("google_dorks", "google_dorks.md", 20),
    ("gau", "gau.txt", 20),
    ("waybackurls", "waybackurls.txt", 20),
    ("urlfinder", "urlfinder.txt", 20),
)

#: The report has five sections including two tables; 1800 tokens truncated it
#: mid-table, which reads as a broken tool rather than a short answer.
MAX_OUTPUT_TOKENS = 4000

#: Sent as the system message where the provider supports one.
AI_SYSTEM_PROMPT = (
    "You are a senior application-security analyst supporting authorised "
    "penetration testing and bug bounty work. You report only what the supplied "
    "evidence supports, cite the artifact behind every claim, and never invent "
    "hostnames, versions, CVE identifiers, or findings. You prefer a short "
    "accurate answer to a complete-looking one."
)


def _read_text(path: Path, limit: int = MAX_CHARS_PER_FILE) -> str:
    if not path.exists() or not path.is_file():
        return ""
    data = path.read_text(errors="replace")
    return data[:limit]


def _read_lines(path: Path, limit: int = MAX_ROWS_PER_FILE) -> list[str]:
    txt = _read_text(path)
    return [line.strip() for line in txt.splitlines() if line.strip()][:limit]


def _all_rows(path: Path) -> list[str]:
    """Return every row of an artifact, whatever shape it is on disk.

    A ``.json`` file holding an array is one physical line but many logical
    rows, so splitting on newlines would hand the model a single unreadable
    blob. Each element is emitted compactly instead.
    """
    if not path.is_file():
        return []
    raw = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return [line.strip() for line in raw.splitlines() if line.strip()]
        if isinstance(payload, list):
            return [json.dumps(item, separators=(",", ":"), default=str) for item in payload]
        return [json.dumps(payload, separators=(",", ":"), default=str)]
    return [line.strip() for line in raw.splitlines() if line.strip()]


class AIAnalysisTool(BaseTool):
    name = "ai_analysis"
    binary_name = None
    category = ToolCategory.AI
    description = "AI analyst: ranks the parameter/endpoint test surface, attack paths and evidence gaps"
    parallel_group = "analysis"

    def availability_error(self) -> str | None:
        if not has_any_ai_api_key():
            return "Configure at least one AI API key in Settings to use AI Analysis"
        return None

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        context = self._build_context(domain, out_dir)
        prompt = self._build_prompt(domain, context)

        prompt_path = out_dir / "ai_analysis_prompt.md"
        context_path = out_dir / "ai_analysis_context.json"
        analysis_path = out_dir / "ai_analysis.md"
        prompt_path.write_text(prompt, encoding="utf-8")
        context_path.write_text(json.dumps(context, indent=2), encoding="utf-8")

        try:
            markdown, provider = await self._call_first_available_ai(prompt)
            if not markdown.strip():
                raise RuntimeError("AI provider returned an empty response")
            final = markdown.strip() + f"\n\n---\nGenerated by `{provider}` from ShadowGrid phase outputs.\n"
            analysis_path.write_text(final, encoding="utf-8")
            return RunResult(final, "", 0, 0.0)
        except Exception as exc:
            fallback = self._fallback_markdown(domain, context, prompt, str(exc))
            analysis_path.write_text(fallback, encoding="utf-8")
            # returncode 0 because the Markdown artifact was still produced; expose provider error in the content.
            return RunResult(fallback, "", 0, 0.0)

    def _build_context(self, domain: str, out_dir: Path) -> dict[str, Any]:
        """Assemble a bounded, evidence-first context for the model.

        Artifacts are filled in the order below, which is the order they are
        worth tokens: a parameter with a risk hint beats a thousand archived
        URLs. Once the character budget is spent the remaining artifacts still
        appear with their real ``total``, so the model can see — and report —
        what it was not shown.
        """
        context: dict[str, Any] = {"domain": domain, "artifacts": {}}
        remaining = MAX_CONTEXT_CHARS

        for key, filename, row_cap in ARTIFACT_SOURCES:
            path = out_dir / filename
            rows = _all_rows(path)
            sample: list[str] = []
            for row in rows[:row_cap]:
                trimmed = row[:MAX_ROW_CHARS]
                if len(trimmed) > remaining:
                    break
                sample.append(trimmed)
                remaining -= len(trimmed)
            context["artifacts"][key] = {
                "file": filename,
                "exists": path.exists() and bool(rows),
                "total": len(rows),
                "sample": sample,
                "truncated": len(sample) < len(rows),
            }

        screenshots_dir = out_dir / "screenshots"
        screenshots = []
        if screenshots_dir.exists():
            for f in sorted(screenshots_dir.rglob("*")):
                if f.is_file() and f.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
                    screenshots.append(str(f.relative_to(out_dir)))
        context["screenshots"] = screenshots[:40]
        return context

    def _build_prompt(self, domain: str, context: dict[str, Any]) -> str:
        compact = json.dumps(context, separators=(",", ":"))
        empty = sorted(
            key for key, artifact in context.get("artifacts", {}).items()
            if not artifact.get("exists")
        )
        # Naming the empty artifacts explicitly stops the model inferring that
        # a quiet tool found nothing of interest, when it never ran at all.
        missing = ", ".join(empty) if empty else "none"
        return (
            f"{GENERIC_AI_PROMPT}\n\n"
            f"# Context\n\n"
            f"Target domain: {domain}\n"
            f"Artifacts with no data (tool did not run, or returned nothing): {missing}\n\n"
            f"```json\n{compact}\n```\n"
        )

    def _fallback_markdown(self, domain: str, context: dict[str, Any], prompt: str, error: str) -> str:
        artifacts = context.get("artifacts", {})
        subdomains = artifacts.get("subdomains", {}).get("sample", [])[:20]
        alive_urls = artifacts.get("alive_urls", {}).get("sample", [])[:20]
        nuclei = artifacts.get("nuclei", {}).get("sample", [])[:20]
        dorks = artifacts.get("google_dorks", {}).get("sample", [])[:20]
        params = artifacts.get("params", {}).get("sample", [])[:20]
        return "\n".join([
            f"# ShadowGrid AI Analysis — {domain}",
            "",
            "> No AI provider answered, so this is ShadowGrid's own triage skeleton.",
            "> It ranks by artifact presence only — none of it is analysis.",
            f"> Error: `{clean_tool_output(error)[:300]}`",
            "",
            "## Verdict",
            "- AI analysis unavailable; the evidence below is unranked.",
            f"- Parameterised URLs mined: {len(params)} in sample [params]",
            f"- Alive services: {len(alive_urls)} in sample [alive_urls]",
            f"- Template findings: {len(nuclei)} in sample [nuclei]",
            "",
            "## Priority Test Surface",
            "| # | Target | Why it stands out | Evidence | First check |",
            "|---|---|---|---|---|",
            *[
                f"| {index} | `{value}` | Carries parameters | [params] | "
                "Replay with each parameter altered in turn |"
                for index, value in enumerate(params[:10], start=1)
            ],
            *[
                f"| {index} | `{value}` | Verified responding | [alive_urls] | "
                "Review auth, then exposed paths |"
                for index, value in enumerate((alive_urls or subdomains)[:10], start=len(params[:10]) + 1)
            ],
            "",
            "## Gaps In This Assessment",
            "- No AI provider answered, so nothing here is prioritised by reasoning.",
            f"- Google dorks generated: {len(dorks)} — open them manually [google_dorks].",
            "- Re-run with a working AI key in Settings, or paste the prompt below",
            "  into any assistant.",
            "",
            "## Prompt For External AI",
            "```text",
            prompt,
            "```",
        ])

    async def _call_first_available_ai(self, prompt: str) -> tuple[str, str]:
        if os.environ.get("OPENAI_API_KEY"):
            return await self._call_openai(prompt)

        if os.environ.get("ANTHROPIC_API_KEY"):
            return await self._call_anthropic(prompt)

        if os.environ.get("GOOGLE_AI_API_KEY"):
            return await self._call_google(prompt)

        if os.environ.get("DEEPSEEK_API_KEY"):
            return await self._call_openai_compatible(prompt, "deepseek", "https://api.deepseek.com/chat/completions", os.environ["DEEPSEEK_API_KEY"], "deepseek-chat")

        if os.environ.get("GROQ_API_KEY"):
            return await self._call_openai_compatible(prompt, "groq", "https://api.groq.com/openai/v1/chat/completions", os.environ["GROQ_API_KEY"], "llama-3.1-8b-instant")

        raise RuntimeError("No supported AI API key is configured")

    async def _call_openai(self, prompt: str) -> tuple[str, str]:
        return await self._call_openai_compatible(prompt, "openai", "https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"], "gpt-4o-mini")

    async def _call_openai_compatible(self, prompt: str, provider: str, url: str, key: str, model: str) -> tuple[str, str]:
        payload = {
            "model": model,
            # Low temperature: this is evidence reporting, not ideation.
            "temperature": 0.1,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "messages": [
                {"role": "system", "content": AI_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=90)) as session:
            async with session.post(url, headers=headers, json=payload) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(f"{provider} API returned {resp.status}: {text[:500]}")
                data = json.loads(text)
                return data["choices"][0]["message"]["content"], provider

    async def _call_anthropic(self, prompt: str) -> tuple[str, str]:
        payload = {
            "model": "claude-3-5-haiku-latest",
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.1,
            "system": AI_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=90)) as session:
            async with session.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(f"anthropic API returned {resp.status}: {text[:500]}")
                data = json.loads(text)
                return "\n".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"), "anthropic"

    async def _call_google(self, prompt: str) -> tuple[str, str]:
        key = os.environ["GOOGLE_AI_API_KEY"]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": AI_SYSTEM_PROMPT}]},
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": MAX_OUTPUT_TOKENS},
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=90)) as session:
            async with session.post(url, json=payload) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(f"google AI API returned {resp.status}: {text[:500]}")
                data = json.loads(text)
                parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                return "\n".join(p.get("text", "") for p in parts), "google"

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        out_dir = self.output_dir / domain
        analysis_path = out_dir / "ai_analysis.md"
        prompt_path = out_dir / "ai_analysis_prompt.md"
        content = _read_text(analysis_path, 120_000) or result.stdout
        return [{
            "title": f"AI Recon Analysis — {domain}",
            "domain": domain,
            "markdown": content,
            "path": str(analysis_path.relative_to(self.output_dir)) if analysis_path.exists() else "",
            "prompt_path": str(prompt_path.relative_to(self.output_dir)) if prompt_path.exists() else "",
            "source": "ai_analysis",
        }]
