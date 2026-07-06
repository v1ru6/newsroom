from newsroom.config import Config
from newsroom.ingest.rss import dedupe, fetch_all, load_fixture


def test_fixture_ingestion(fixture_feed):
    config = Config(max_items_per_source=50)
    articles, health = load_fixture(fixture_feed, config)
    assert health.status == "fixture"
    assert health.items_fetched == 6
    assert all(a.url and a.title for a in articles)
    assert articles[0].published_at is not None
    assert articles[0].published_at.tzinfo is not None


def test_fetch_all_prefers_fixture(fixture_config):
    articles, health = fetch_all(fixture_config)
    assert len(health) == 1
    assert health[0].status == "fixture"
    assert articles


def test_dedupe_removes_duplicate_titles(fixture_feed):
    config = Config(max_items_per_source=50)
    articles, _ = load_fixture(fixture_feed, config)
    unique, removed = dedupe(articles)
    assert removed == 1  # the syndicated FortiOS copy
    titles = [a.title for a in unique]
    assert len(titles) == len(set(titles))


def test_max_items_per_source_limits(fixture_feed):
    config = Config(max_items_per_source=2)
    articles, _ = load_fixture(fixture_feed, config)
    assert len(articles) == 2
