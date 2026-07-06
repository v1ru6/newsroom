import json

import pytest

from newsroom.config import Config, KEVConfig
from newsroom.store import Store
from newsroom.workflow import run_workflow


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
