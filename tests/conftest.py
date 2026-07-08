"""Shared pytest fixtures and readable test output labels.

Fixtures here point tests at local RSS/KEV files and temp output folders. The
description map makes `pytest` output explain the intent of each test line.
"""

from pathlib import Path

import pytest

from newsroom.config import Config, KEVConfig

FIXTURES = Path(__file__).parent / "fixtures"

TEST_DESCRIPTIONS = {
    "test_prompt_injection_blocks_llm_but_keeps_deterministic_alert": (
        "Prompt injection blocks optional LLM triage while deterministic scoring can still alert."
    ),
    "test_malformed_model_output_is_dropped": (
        "Malformed model JSON is rejected by the output-handling gate."
    ),
    "test_unsupported_model_claim_is_rejected": (
        "Unsupported LLM claims are dropped before ledger promotion."
    ),
    "test_sensitive_values_are_redacted_from_display_outputs": (
        "Secrets and instruction-like text are redacted from exported artifacts."
    ),
    "test_coordinator_suppresses_when_ledger_is_empty": (
        "Coordinator suppresses when no reviewed ledger entries exist."
    ),
    "test_source_health_reports_disabled_and_errors": (
        "Disabled and failing feeds are reported in source health without stopping the run."
    ),
    "test_summary_and_headers": (
        "Summary API returns counts and security headers."
    ),
    "test_alerts_redacted": (
        "Alerts API redacts instruction-like source text."
    ),
    "test_static_and_404": (
        "Static console serves index and unknown API routes return 404."
    ),
    "test_static_traversal_blocked": (
        "Static server blocks path traversal outside the web directory."
    ),
    "test_review_requires_custom_header": (
        "Alert review writes require the custom local header."
    ),
    "test_review_approve_flow": (
        "Alert review approve flow persists status and rejects bad actions."
    ),
    "test_monitor_api_excludes_fixture_rows": (
        "Live API hides seeded fixture rows while keeping real source rows visible."
    ),
    "test_cli_fixture_run": (
        "CLI run succeeds against the offline fixture feed."
    ),
    "test_cli_prompt_injection_fixture_run": (
        "CLI run succeeds against the prompt-injection fixture."
    ),
    "test_cli_llm_requires_provider_and_model": (
        "CLI fails clearly when LLM mode lacks provider/model config."
    ),
    "test_defaults": (
        "Default config sets thresholds, weights, and LLM disabled mode."
    ),
    "test_load_yaml_and_override": (
        "YAML config loads and CLI-style overrides win."
    ),
    "test_none_overrides_ignored": (
        "None overrides are ignored so config file values survive."
    ),
    "test_invalid_thresholds_rejected": (
        "Invalid threshold ranges are rejected by Pydantic validation."
    ),
    "test_source_defaults_and_llm_validation": (
        "Source IDs default cleanly and enabled LLM config requires provider/model."
    ),
    "test_fixture_ingestion": (
        "Fixture RSS parses into dated articles and fixture source health."
    ),
    "test_fetch_all_prefers_fixture": (
        "Fixture mode bypasses live feeds and returns one fixture health row."
    ),
    "test_dedupe_removes_duplicate_titles": (
        "RSS dedupe removes the syndicated duplicate article."
    ),
    "test_max_items_per_source_limits": (
        "Per-source item limit is enforced during ingestion."
    ),
    "test_normalize_strips_zero_width_and_entities": (
        "Safety normalization catches zero-width and HTML-entity injection text."
    ),
    "test_normalize_nfkc_homoglyph_width": (
        "Safety normalization catches NFKC width tricks."
    ),
    "test_grounded_evidence_kept": (
        "Reviewer keeps findings backed by verbatim source evidence."
    ),
    "test_ungrounded_evidence_dropped": (
        "Reviewer drops fabricated evidence before ledger promotion."
    ),
    "test_spotlight_delimit_uses_unguessable_nonce_markers": (
        "LLM spotlight delimiters use a fresh nonce that source text cannot pre-forge."
    ),
    "test_spotlight_base64_mode_encodes_source_text": (
        "Base64 spotlight mode removes raw source text from the prompt channel."
    ),
    "test_spotlight_datamark_interleaves_marker": (
        "Datamark spotlight mode inserts the marker between source words."
    ),
    "test_evasive_injections_block_llm_path_and_render_inert": (
        "Evasive prompt injections trip LLM blocking and render redacted in artifacts."
    ),
    "test_flagged_alert_enters_pending_review": (
        "Tripwired alerts enter pending human review and can be approved."
    ),
    "test_extract_cves_confident_only": (
        "CVE extraction keeps valid IDs, decodes entities, and ignores weak patterns."
    ),
    "test_parse_and_upsert_kev": (
        "CISA KEV fixture parses and persists into the SQLite cache."
    ),
    "test_record_mentions": (
        "CVE mentions persist and report whether each article hits KEV."
    ),
    "test_vulnerability_classifier_scores_high": (
        "Vulnerability expert scores CVE, zero-day, RCE, and patch signals high."
    ),
    "test_active_attack_classifier_detects_exploitation": (
        "Active attack expert detects exploitation-in-the-wild language."
    ),
    "test_breach_classifier_scores_breach_not_benign": (
        "Breach expert scores exposed data and ignores benign announcements."
    ),
    "test_confidence_penalizes_thin_undated_hedged": (
        "Confidence expert penalizes thin, undated, hedged stories."
    ),
    "test_weighted_average": (
        "Weighted average combines classifier scores and handles empty inputs."
    ),
    "test_threshold_routing": (
        "Default thresholds alert on high-risk news and suppress benign news."
    ),
    "test_high_threshold_suppresses": (
        "Raised thresholds suppress an otherwise strong vulnerability story."
    ),
    "test_low_threshold_alerts": (
        "Lowered thresholds alert on lower aggregate score stories."
    ),
    "test_confidence_gate_blocks_keyword_heavy_rumor": (
        "Low confidence suppresses keyword-heavy rumors despite threat terms."
    ),
    "test_kev_boost_bounded_and_capped": (
        "KEV corroboration adds a bounded 0.10 score boost."
    ),
    "test_kev_boost_never_bypasses_confidence_gate": (
        "KEV boost cannot bypass the confidence suppression gate."
    ),
    "test_recent_vulnerability_plus_active_exploitation_promotes_to_alert": (
        "Current vulnerability plus active exploitation promotes below-threshold items."
    ),
    "test_stale_cross_signal_item_stays_watchlist": (
        "Stale cross-signal items stay watchlist instead of promoted alert."
    ),
    "test_kev_active_watch_item_promotes_to_alert": (
        "KEV plus active attack signal promotes a watch item to alert."
    ),
    "test_promotions_respect_operator_watch_threshold": (
        "Promotion rules still respect the configured watch threshold floor."
    ),
    "test_run_roundtrip": (
        "Run metadata persists and reads back with counts and errors."
    ),
    "test_article_and_hash_tracking": (
        "Article hash tracking updates known stories without duplicate article rows."
    ),
    "test_decision_and_health_recorded": (
        "Decisions and source health are recorded with safety notes."
    ),
    "test_meta": (
        "Store metadata reads and writes KEV cache timestamps."
    ),
    "test_alert_lifecycle": (
        "Alert-once lifecycle updates existing alert rows and records events."
    ),
    "test_watch_loop_runs_and_survives_errors": (
        "Watch scheduler keeps running after a failed pipeline iteration."
    ),
    "test_end_to_end_fixture_run": (
        "Full fixture workflow produces expected alerts, watchlist, suppressions, and artifacts."
    ),
    "test_high_threshold_end_to_end": (
        "End-to-end run with very high thresholds produces no alerts."
    ),
    "test_alert_ids_stable_across_runs": (
        "Alert IDs are stable across equivalent fresh database runs."
    ),
    "test_second_run_is_deduped_and_alerts_once": (
        "Second run skips known articles and does not duplicate alert rows."
    ),
    "test_kev_corroboration_boost_end_to_end": (
        "End-to-end KEV enrichment boosts the matching CVE alert."
    ),
}


def pytest_collection_modifyitems(config, items):
    """Show compact descriptions in normal verbose pytest output."""
    for item in items:
        name = getattr(item, "originalname", None) or item.name.split("[", 1)[0]
        description = TEST_DESCRIPTIONS.get(name)
        if description:
            item._nodeid = f"{item.nodeid} - {description}"


@pytest.fixture
def fixture_feed() -> Path:
    return FIXTURES / "rss_sample.xml"


@pytest.fixture
def prompt_injection_feed() -> Path:
    return FIXTURES / "rss_prompt_injection.xml"


@pytest.fixture
def fixture_config(fixture_feed, tmp_path) -> Config:
    return Config(fixture_path=fixture_feed, output_dir=tmp_path / "output",
                  db_path=tmp_path / "output" / "newsroom.db",
                  kev=KEVConfig(enabled=False))
