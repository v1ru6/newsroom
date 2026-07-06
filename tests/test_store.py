import json
from datetime import datetime, timezone

import pytest

from newsroom.models import ArticleDecision, ClassifierResult, NewsArticle, SourceHealth, ThreatAlert, stable_id
from newsroom.store import Store

NOW = datetime(2026, 7, 4, 12, 0, tzinfo=timezone.utc)

A1_URL = "https://example.com/a1"
A1_ID = stable_id(A1_URL)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "newsroom.db")
    yield s
    s.close()


def article(url=A1_URL, summary="A critical zero-day."):
    # invariant: NewsArticle.id == stable_id(url) (see ingest/rss.normalize_entries)
    return NewsArticle(id=stable_id(url), title=f"Story {stable_id(url)[:4]}", summary=summary,
                       source="test", source_id="test", url=url, published_at=NOW)


def decision(art, score=0.61, decision_="alert"):
    return ArticleDecision(
        article=art,
        results=[ClassifierResult(classifier="vulnerability", score=score, label="high")],
        average_score=score, threshold=0.55, decision=decision_,
    )


def alert_for(art, score=0.61, severity="high"):
    return ThreatAlert(alert_id=f"al-{art.id}", title=art.title, severity=severity,
                       score=score, why_it_matters="reasons", source_url=art.url,
                       source=art.source, recommended_action="review",
                       safety_notes=["promoted: test signal"])


def test_run_roundtrip(store):
    run_id = store.begin_run(NOW)
    assert isinstance(run_id, int)
    store.finish_run(run_id, finished_at=NOW, articles_seen=5, new_articles=3,
                     duplicates_removed=1, alert_count=2, watch_count=1,
                     suppressed_count=2, errors=["boom"])
    runs = store.recent_runs(limit=5)
    assert runs[0]["run_id"] == run_id
    assert runs[0]["alert_count"] == 2
    assert json.loads(runs[0]["errors_json"]) == ["boom"]


def test_article_and_hash_tracking(store):
    run_id = store.begin_run(NOW)
    art = article()
    store.upsert_article(art, run_id, text_hash="h1")
    assert store.known_text_hashes() == {A1_ID: "h1"}
    # re-upsert with new hash updates, does not duplicate
    store.upsert_article(art, run_id, text_hash="h2")
    assert store.known_text_hashes() == {A1_ID: "h2"}


def test_decision_and_health_recorded(store):
    run_id = store.begin_run(NOW)
    art = article()
    store.upsert_article(art, run_id, text_hash="h1")
    recorded = decision(art)
    recorded.safety_notes = ["promoted: test signal"]
    store.record_decision(run_id, recorded)
    rows = store.search_decisions(limit=10)
    assert rows[0]["decision"] == "alert"
    assert rows[0]["title"] == art.title
    assert rows[0]["threshold"] == 0.55
    assert json.loads(rows[0]["safety_notes_json"]) == ["promoted: test signal"]
    store.record_source_health(run_id, SourceHealth(
        name="test", source_id="test", url="u", status="error", error="timeout"))
    health = store.latest_source_health()
    assert health[0]["status"] == "error"


def test_meta(store):
    assert store.get_meta("kev_fetched_at") is None
    store.set_meta("kev_fetched_at", "2026-07-04T00:00:00+00:00")
    assert store.get_meta("kev_fetched_at") == "2026-07-04T00:00:00+00:00"


def test_alert_lifecycle(store):
    run_id = store.begin_run(NOW)
    art = article()
    store.upsert_article(art, run_id, text_hash="h1")

    assert store.record_alert(alert_for(art, 0.61, "high")) == "created"
    # same story crosses again with same severity band
    assert store.record_alert(alert_for(art, 0.58, "high")) == "re_crossed"
    # severity band changes
    assert store.record_alert(alert_for(art, 0.74, "critical")) == "severity_changed"

    rows = store.recent_alerts()
    assert len(rows) == 1  # never a duplicate row
    row = rows[0]
    assert row["first_score"] == 0.61
    assert row["last_score"] == 0.74
    assert row["max_score"] == 0.74
    assert row["severity"] == "critical"
    assert row["status_changed_at"] is not None
    assert json.loads(row["safety_notes_json"]) == ["promoted: test signal"]

    events = store.alert_events(row["alert_id"])
    assert [e["event_type"] for e in events] == ["created", "re_crossed", "severity_changed"]
