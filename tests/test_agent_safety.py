import json
from datetime import datetime, timezone

from newsroom.config import Config, KEVConfig, SourceConfig
from newsroom.ingest.rss import articles_to_normalized_items, fetch_all
from newsroom.llm import validate_model_output
from newsroom.models import AgentFinding, NewsArticle, stable_id
from newsroom.safety import review_findings
from newsroom.workflow import coordinator_decisions, run_workflow


def test_prompt_injection_blocks_llm_but_keeps_deterministic_alert(prompt_injection_feed, tmp_path):
    config = Config(
        fixture_path=prompt_injection_feed,
        output_dir=tmp_path / "output",
        db_path=tmp_path / "output" / "newsroom.db",
        kev=KEVConfig(enabled=False),
        llm={"enabled": True, "provider": "mock", "model": "mock-model"},
    )
    report = run_workflow(config)

    assert len(report.alerts) == 1
    assert report.alerts[0].severity == "critical"
    assert "LLM01 Prompt Injection" in report.alerts[0].owasp_categories
    assert report.safety_report.counts["llm_blocked"] >= 1
    assert report.safety_report.llm_blocked_items


def test_malformed_model_output_is_dropped(prompt_injection_feed):
    article = _article()
    item = articles_to_normalized_items([article])[0]
    findings, gates = validate_model_output("{not-json", item)
    assert findings == []
    assert gates[0].status == "drop"
    assert gates[0].owasp_category == "LLM05 Improper Output Handling"


def test_unsupported_model_claim_is_rejected():
    finding = AgentFinding(
        finding_id="unsupported",
        agent_id="llm_triage_agent",
        item_id="item-1",
        article_id="article-1",
        score=0.9,
        label="high",
        claim="unsupported claim",
        evidence=[],
        source_refs=[],
        supported=False,
    )
    kept, gates = review_findings([finding], {})
    assert kept == []
    assert gates[0].status == "drop"
    assert gates[0].owasp_category == "LLM09 Misinformation"


def test_sensitive_values_are_redacted_from_display_outputs(prompt_injection_feed, tmp_path):
    secret_value = "api_" + "key=" + "TESTONLYDUMMYVALUE1234567890"
    feed = tmp_path / "rss_prompt_injection_with_secret.xml"
    feed.write_text(prompt_injection_feed.read_text().replace(
        "DUMMY_SECRET_MARKER", secret_value
    ))
    config = Config(fixture_path=feed, output_dir=tmp_path / "output",
                    db_path=tmp_path / "output" / "newsroom.db",
                    kev=KEVConfig(enabled=False))
    run_workflow(config)

    combined = "\n".join(
        (tmp_path / "output" / name).read_text()
        for name in [
            "alerts.jsonl",
            "decisions.jsonl",
            "evidence_ledger.jsonl",
            "index.html",
            "run_report.md",
        ]
    )
    assert "TESTONLYDUMMYVALUE1234567890" not in combined
    assert "[REDACTED_SECRET]" in combined
    assert "[REDACTED_INSTRUCTION]" in combined


def test_coordinator_suppresses_when_ledger_is_empty():
    article = _article()
    item = articles_to_normalized_items([article])[0]
    state = {
        "config": Config(),
        "articles": [article],
        "articles_by_id": {article.id: article},
        "items": [item],
        "evidence_ledger": [],
    }
    result = coordinator_decisions(state)
    decision = result["decisions"][0]
    assert decision.decision == "suppressed"
    assert decision.suppression_reason == "no reviewed ledger entries"


def test_source_health_reports_disabled_and_errors(monkeypatch):
    disabled = SourceConfig(name="disabled", url="https://example.com/feed.xml", enabled=False)
    articles, health = fetch_all(Config(sources=[disabled]))
    assert articles == []
    assert health[0].status == "disabled"

    def fail_get(*args, **kwargs):
        import httpx

        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("newsroom.ingest.rss.httpx.get", fail_get)
    broken = SourceConfig(name="broken", url="https://example.com/feed.xml")
    articles, health = fetch_all(Config(sources=[broken]))
    assert articles == []
    assert health[0].status == "error"
    assert "timed out" in health[0].error


def _article() -> NewsArticle:
    return NewsArticle(
        id=stable_id("https://example.com/a"),
        title="Critical zero-day CVE-2026-9999 actively exploited",
        summary=(
            "A critical remote code execution flaw is actively exploited by ransomware "
            "groups. Emergency patches are available."
        ),
        source="test",
        source_id="test",
        url="https://example.com/a",
        published_at=datetime.now(timezone.utc),
    )
