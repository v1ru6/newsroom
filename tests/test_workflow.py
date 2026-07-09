"""End-to-end workflow tests.

These run the LangGraph pipeline against fixture feeds and temp databases to
verify alert/watch/suppress routing, artifact exports, stable IDs, cross-run
dedupe, alert-once behavior, and KEV score boosting.
"""

import json
from datetime import datetime, timezone

import pytest
from newsroom.config import Config, KEVConfig, LLMConfig
from newsroom.ingest.rss import articles_to_normalized_items
from newsroom.models import EvidenceLedgerEntry, NewsArticle, stable_id
from newsroom.store import Store
from newsroom.workflow import coordinator_decisions, run_workflow

def test_end_to_end_fixture_run(fixture_config):
    report = run_workflow(fixture_config)

    assert report.articles_seen == 6
    assert report.duplicates_removed == 1

    # FortiOS zero-day and healthcare breach alert; the APT campaign lands on
    # the watchlist; the newsletter and the thin rumor are suppressed.
    assert len(report.alerts) == 2
    alert_titles = " ".join(a.title for a in report.alerts)
    assert "CVE-2026-1234" in alert_titles
    assert "data breach" in alert_titles
    assert len(report.watchlist) == 1
    assert "APT" in report.watchlist[0].article.title
    suppressed_titles = " ".join(d.article.title for d in report.suppressed)
    assert "newsletter" in suppressed_titles
    assert "Rumor" in suppressed_titles

    output_dir = fixture_config.output_dir
    alerts = [json.loads(line) for line in (output_dir / "alerts.jsonl").read_text().splitlines()]
    assert len(alerts) == 2
    assert all(a["score"] >= fixture_config.alert_threshold for a in alerts)

    decisions = (output_dir / "decisions.jsonl").read_text().splitlines()
    assert len(decisions) == 5  # 6 seen - 1 duplicate

    report_md = (output_dir / "run_report.md").read_text()
    assert "Source Health" in report_md and "fixture" in report_md

    manifest = json.loads((output_dir / "run_manifest.json").read_text())
    assert manifest["counts"]["alerts"] == 2
    assert manifest["counts"]["ledger_entries"] > 0
    assert manifest["counts"]["gate_decisions"] > 0

    ledger = (output_dir / "evidence_ledger.jsonl").read_text().splitlines()
    assert ledger
    safety = json.loads((output_dir / "safety_report.json").read_text())
    assert safety["counts"]["pass"] > 0
    trace = (output_dir / "agent_trace.jsonl").read_text().splitlines()
    assert trace

    data = json.loads((output_dir / "data.json").read_text())
    assert data["counts"]["alerts"] == 2
    assert data["alerts"][0]["score"] >= data["alerts"][1]["score"]
    assert all(set(a) >= {"title", "severity", "score", "source", "url"}
               for a in data["alerts"])
    # static console copied verbatim from the package
    assert (output_dir / "index.html").exists()
    assert (output_dir / "app.js").exists()
    assert "renderAlerts" in (output_dir / "app.js").read_text()
    assert '<script src="app.js"></script>' in (output_dir / "index.html").read_text()


def test_high_threshold_end_to_end(fixture_config):
    fixture_config = fixture_config.model_copy(
        update={"alert_threshold": 0.99, "watch_threshold": 0.98}
    )
    report = run_workflow(fixture_config)
    assert report.alerts == []


def test_alert_ids_stable_across_runs(fixture_feed, tmp_path):
    # fresh DBs so cross-run dedupe does not hide the second run's alerts
    cfg1 = Config(fixture_path=fixture_feed, output_dir=tmp_path / "o1",
                  db_path=tmp_path / "o1" / "n.db", kev=KEVConfig(enabled=False))
    cfg2 = Config(fixture_path=fixture_feed, output_dir=tmp_path / "o2",
                  db_path=tmp_path / "o2" / "n.db", kev=KEVConfig(enabled=False))
    first = run_workflow(cfg1)
    second = run_workflow(cfg2)
    assert [a.alert_id for a in first.alerts] == [a.alert_id for a in second.alerts]


def test_second_run_is_deduped_and_alerts_once(fixture_config):
    report1 = run_workflow(fixture_config)
    assert len(report1.alerts) >= 1
    first_decisions_export = (fixture_config.output_dir / "decisions.jsonl").read_text()

    report2 = run_workflow(fixture_config)
    # every article already known: nothing new to classify or alert
    assert report2.articles_seen == report1.articles_seen  # fetched the same feed
    assert (fixture_config.output_dir / "decisions.jsonl").read_text() == first_decisions_export
    store = Store(fixture_config.db_path)
    try:
        runs = store.recent_runs()
        assert runs[0]["new_articles"] == 0
        alerts = store.recent_alerts()
        # alert rows equal to run-1 alert count, no duplicates from run 2
        assert len(alerts) == len(report1.alerts)
        assert all(a["event_count"] == 1 for a in alerts)  # run 2 skipped known items
    finally:
        store.close()


def _coordinator_state():
    article = NewsArticle(
        id=stable_id("https://example.com/a"),
        title="Critical zero-day actively exploited",
        summary="A critical flaw sees active exploitation by ransomware groups.",
        source="test", source_id="test", url="https://example.com/a",
        published_at=datetime.now(timezone.utc),
    )
    item = articles_to_normalized_items([article])[0]
    return article, item


def _ledger_entry(item, agent_id, score, suffix):
    return EvidenceLedgerEntry(
        ledger_id=stable_id(item.id, agent_id, suffix), agent_id=agent_id,
        item_id=item.id, article_id=item.article_id, title=item.title,
        source_url=item.canonical_url, source=item.source, source_id=item.source_id,
        trust_level=item.trust_level, claim=f"claim {suffix}", score=score, label="high",
    )


def test_multiple_llm_ledger_entries_collapse_to_max_score_for_scoring():
    # The LLM can report several findings per item; only the strongest one may
    # enter the weighted average, or one expert gets counted multiple times.
    article, item = _coordinator_state()
    state = {
        "config": Config(),
        "articles_by_id": {article.id: article},
        "items": [item],
        "evidence_ledger": [
            _ledger_entry(item, "vulnerability_agent", 0.6, "v1"),
            _ledger_entry(item, "llm_triage_agent", 0.4, "l1"),
            _ledger_entry(item, "llm_triage_agent", 0.9, "l2"),
        ],
    }
    decision = coordinator_decisions(state)["decisions"][0]
    classifiers = sorted(r.classifier for r in decision.results)
    assert classifiers == ["llm_triage", "vulnerability"]
    llm_result = next(r for r in decision.results if r.classifier == "llm_triage")
    assert llm_result.score == 0.9
    # vulnerability 0.6 and llm_triage 0.9, both at default weight 1.0
    assert decision.average_score == pytest.approx(0.75)
    # all entries still reach the ledger trail; only scoring input is deduped
    assert len(decision.ledger_entry_ids) == 3


def test_llm_corroboration_moves_watchlist_item_to_alert(fixture_feed, tmp_path):
    # Baseline (LLM disabled): the APT campaign story lands on the watchlist.
    baseline_cfg = Config(fixture_path=fixture_feed, output_dir=tmp_path / "b",
                          db_path=tmp_path / "b" / "n.db", kev=KEVConfig(enabled=False))
    baseline = run_workflow(baseline_cfg)
    assert any("APT" in d.article.title for d in baseline.watchlist)

    # With a fake provider corroborating at 0.95, the blended average crosses
    # the alert threshold: (1.65 + 0.95) / 4.5 = 0.578 >= 0.55.
    responses = tmp_path / "llm_responses.json"
    responses.write_text(json.dumps({"_default": {"findings": [{
        "score": 0.95, "label": "high",
        "claim": "model corroborates ongoing exploitation",
        "evidence": ["active exploitation"],
        "source_refs": ["https://example.com/articles/apt-energy-campaign"],
    }]}}))
    cfg = Config(fixture_path=fixture_feed, output_dir=tmp_path / "o",
                 db_path=tmp_path / "o" / "n.db", kev=KEVConfig(enabled=False),
                 llm=LLMConfig(enabled=True, provider="fake", model="fixture",
                               fixture_path=responses))
    report = run_workflow(cfg)
    assert any("APT" in a.title for a in report.alerts)
    data = json.loads((tmp_path / "o" / "data.json").read_text())
    apt = next(a for a in data["alerts"] if "APT" in a["title"])
    assert any(r["classifier"] == "active_attack"
               and r["reasons"] == ["llm: model corroborates ongoing exploitation"]
               for r in apt["results"])


def test_kev_corroboration_boost_end_to_end(fixture_feed, tmp_path):
    cfg = Config(fixture_path=fixture_feed, output_dir=tmp_path / "o",
                 db_path=tmp_path / "o" / "n.db")
    store = Store(cfg.db_path)
    store.upsert_kev([{"cve_id": "CVE-2026-1234", "vendor": "Fortinet",
                       "product": "FortiOS", "name": "RCE",
                       "date_added": "2026-07-01", "ransomware_use": "Known"}])
    store.set_meta("kev_fetched_at", "2999-01-01T00:00:00+00:00")  # skip network
    report = run_workflow(cfg, store=store)
    forti = next(a for a in report.alerts if "CVE-2026-1234" in a.title)

    baseline_cfg = Config(fixture_path=fixture_feed, output_dir=tmp_path / "b",
                          db_path=tmp_path / "b" / "n.db",
                          kev=KEVConfig(enabled=False))
    baseline = run_workflow(baseline_cfg)
    base_forti = next(a for a in baseline.alerts if "CVE-2026-1234" in a.title)
    assert forti.score == pytest.approx(min(base_forti.score + 0.10, 1.0), abs=1e-4)
    store.close()
