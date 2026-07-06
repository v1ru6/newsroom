# NewsRoom

A personal cyber-threat **situation monitor**. NewsRoom ingests 10 trusted
security feeds, treats every byte of source content as untrusted, scores each
article with a panel of deterministic specialist agents, corroborates CVEs
against CISA KEV, and maintains an alert history in SQLite - rendered as a
dark, dense, keyboard-driven console. Built with Python, Pydantic, LangGraph,
and zero frontend dependencies.

```text
feeds ──> normalize ──> dedupe(cross-run) ──> KEV enrich ──> specialist agents
      ──> review (evidence grounding) ──> safety gates ──> evidence ledger
      ──> coordinator ──> alert-once lifecycle ──> SQLite ──> monitor console
```

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                    # all tests, offline

# The monitor: pipeline every 15 min + console, one process
newsroom watch                            # http://127.0.0.1:8765

# One-shot alternatives
newsroom run --config config.yaml                     # single pipeline run
newsroom run --fixture tests/fixtures/rss_sample.xml  # offline demo data
newsroom serve                                        # console only, no scheduler
```

Console: `j/k` moves through the alert stream, `Enter`/click opens the
inspector, `/` focuses the filter - every shortcut also has a visible control
(severity chips, search box, refresh button). `NEW` badges mark alerts that
arrived since your last visit; `KEV` badges mark stories whose CVE is on the
CISA Known Exploited Vulnerabilities list; `REVIEW` badges mark alerts held
for human review.

## Sources

Ten feeds, all verified live (2026-07-04), one advisory endpoint:

| Tier | Sources |
|---|---|
| Ops / news | SANS ISC, Krebs on Security, The Hacker News, Dark Reading, CyberScoop |
| Research / DFIR | Unit 42, The DFIR Report, Google Project Zero, Recorded Future |
| Trusted voice | Troy Hunt (breach focus; Schneier is the documented swap) |
| Enrichment | CISA KEV - **corroboration metadata, never articles** |

Dropped from the classic candidate list: Threatpost (defunct 2022, feed still
serves stale content), Daily Swig (discontinued 2023), FireEye (brand
retired), Verizon DBIR / SANS reading room / Red Canary report (annual
reports, not feeds), IBM (no clean feed), thisweekin4n6 (re-aggregates the
others - pure duplicates), Didier Stevens (tooling posts the classifiers
would suppress).

## How scoring works

Four deterministic experts score every article 0-1 with verbatim evidence:
`vulnerability` (CVEs, zero-days, RCE, patch urgency), `active_attack`
(exploitation, campaigns, APT, ransomware), `breach_impact` (leaks, exposed
data), and `confidence` (penalizes thin/stale/hedged items). The coordinator
computes a weighted average from gate-checked ledger entries - never raw
text. Articles mentioning a KEV-listed CVE get a flat **+0.10** boost, capped
at 1.0, which never bypasses routing or the confidence gate.

- `average >= alert_threshold` (0.55) → **threat alert**
- `average >= watch_threshold` (0.35) → watchlist
- otherwise, or `confidence < min_confidence` → suppressed with a reason

The scale is compressed because the average spans orthogonal experts: a
single-domain critical story lands near 0.6; only multi-domain stories exceed
0.7. Severity bands (critical ≥ 0.70, high ≥ 0.60) match that scale.

**Alert-once lifecycle**: an article creates at most one alert row ever.
Re-crossings update `last_seen`/`last_score`/`max_score`; severity-band
changes set `status_changed_at`; every transition is an `alert_events` row.

## Security model

Feed content is attacker-controlled input. **Detection is telemetry; structure
is the boundary.**

| Layer | Mechanism |
|---|---|
| Structural immunity | Default classifiers are regex matchers - no instruction-following component exists in the default path |
| Role separation | Untrusted plane (agents see raw text, hold no authority) vs. trusted plane (coordinator holds authority, sees only ledger entries) |
| Tool boundaries | The optional LLM plane has no tools, no network, no write or delivery authority - by construction, with tests |
| Output containment | LLM output must parse into a strict schema; every evidence string must be a **verbatim substring** of the source text or the finding is dropped (anti-hallucination, anti-laundering) |
| Spotlighting | Untrusted text in LLM prompts is wrapped in per-call random-nonce delimiters (`llm.spotlight_mode: delimit`, or `datamark`/`base64`) - a static delimiter is spoofable, a nonce is not |
| Detection tripwires | Prompt-injection and secret regexes run on NFKC-normalized, entity-decoded, zero-width-stripped text; hits fail-close the LLM path per item |
| HITL review | A tripwired item that still alerts enters `pending` review - badged in the console, approve/dismiss from the inspector, never trusted silently |
| Output hygiene | Server-side redaction on every artifact and API response; frontend renders untrusted strings via `textContent` only, under CSP `default-src 'self'`; server binds 127.0.0.1; the one write endpoint requires a custom header no cross-origin page can attach |

## Configuration

Everything lives in [config.yaml](config.yaml): sources and
trust levels, thresholds, classifier weights, `kev:` (enabled/refresh),
`llm:` (disabled by default; provider, spotlighting mode), `db_path`,
`output_dir`. CLI overrides: `--threshold`, `--limit`, `--fixture`,
`--output-dir`, `--db-path`, `--llm`, `--no-kev`, and for watch `--interval`
`--port`.

## Artifacts & API

`output/` after each run: `alerts.jsonl`, `decisions.jsonl`,
`evidence_ledger.jsonl`, `agent_trace.jsonl`, `safety_report.json`,
`run_manifest.json`, `run_report.md`, `data.json` (+ the console files, so
any static server can display the last run). History lives in
`output/newsroom.db`.

Read-only JSON API (loopback): `/api/summary`, `/api/alerts`,
`/api/decisions?q=&decision=`, `/api/timeline?days=`, `/api/sources`,
`/api/kev`, `/api/runs`. One write endpoint:
`POST /api/alerts/<id>/review` (`X-NewsRoom: review` header required).

## Error handling

- A failing feed degrades to an error entry in source health; the run
  continues. KEV fetch failure falls back to the cached catalog.
- A failed scheduled run is logged and recorded; the watch loop continues.
- `newsroom run` exits non-zero when nothing was ingested; `--llm` without
  provider/model config exits with a clear error.

## With more time

- Real LLM provider adapter behind the existing spotlit, schema-validated,
  fail-closed boundary.
- GitHub Advisories / EPSS back as *enrichment adapters* (metadata on items,
  like KEV - never article sources).
- Client-profile relevance scoring; delivery sinks (Slack/webhook) consuming
  `alerts.jsonl`.
