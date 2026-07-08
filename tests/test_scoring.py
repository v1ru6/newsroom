"""Classifier and coordinator-scoring tests.

These build in-memory NewsArticle and ClassifierResult objects to check expert
scores, weighted averages, thresholds, confidence gates, KEV boosts, and
promotion rules without needing RSS or SQLite.
"""

from datetime import datetime, timezone
from newsroom.classifiers import default_classifiers
from newsroom.classifiers.active_attack import ActiveAttackClassifier
from newsroom.classifiers.breach_impact import BreachImpactClassifier
from newsroom.classifiers.confidence import ConfidenceClassifier
from newsroom.classifiers.vulnerability import VulnerabilityClassifier
from newsroom.config import Config
from newsroom.models import ClassifierResult, NewsArticle
from newsroom.alerts import build_alert
from newsroom.scoring import decide, weighted_average

def article(title: str, summary: str, published=True) -> NewsArticle:
    return NewsArticle(
        id="t1",
        title=title,
        summary=summary,
        source="test",
        url="https://example.com/a",
        published_at=datetime.now(timezone.utc) if published else None,
    )

CRITICAL_VULN = article(
    "Critical zero-day CVE-2026-9999 actively exploited",
    "A critical remote code execution flaw (CVE-2026-9999) is actively exploited "
    "in the wild by ransomware groups. An emergency patch is available.",
)
BREACH = article(
    "Retailer breach exposes 2 million customer records",
    "Attackers stole customer data and credentials; the leaked records were "
    "posted online. The breach affects roughly 2 million people.",
)
BENIGN = article(
    "Company announces quarterly webinar schedule",
    "A roundup of upcoming webinars, community events, and product announcements "
    "for partners this quarter.",
)

def test_vulnerability_classifier_scores_high():
    result = VulnerabilityClassifier().classify(CRITICAL_VULN)
    assert result.score >= 0.7
    assert any("CVE" in e for e in result.evidence)

def test_active_attack_classifier_detects_exploitation():
    result = ActiveAttackClassifier().classify(CRITICAL_VULN)
    assert result.score >= 0.4
    assert "active exploitation reported" in result.reasons

def test_breach_classifier_scores_breach_not_benign():
    assert BreachImpactClassifier().classify(BREACH).score >= 0.7
    assert BreachImpactClassifier().classify(BENIGN).score == 0.0

def test_confidence_penalizes_thin_undated_hedged():
    thin = article("Rumor: possible breach", "breach", published=False)
    result = ConfidenceClassifier().classify(thin)
    assert result.score < 0.3
    assert len(result.reasons) == 3


def test_weighted_average():
    results = [
        ClassifierResult(classifier="a", score=1.0, label="high"),
        ClassifierResult(classifier="b", score=0.0, label="none"),
    ]
    assert weighted_average(results, {"a": 1.0, "b": 1.0}) == 0.5
    assert weighted_average(results, {"a": 3.0, "b": 1.0}) == 0.75
    assert weighted_average(results, {}) == 0.5  # unknown classifiers weigh 1.0
    assert weighted_average([], {}) == 0.0

def classify_and_decide(art: NewsArticle, config: Config):
    results = [c.classify(art) for c in default_classifiers()]
    return decide(art, results, config)

def test_threshold_routing():
    config = Config()
    assert classify_and_decide(CRITICAL_VULN, config).decision == "alert"
    assert classify_and_decide(BENIGN, config).decision == "suppressed"

def test_high_threshold_suppresses():
    config = Config(alert_threshold=0.95, watch_threshold=0.9)
    decision = classify_and_decide(CRITICAL_VULN, config)
    assert decision.decision == "suppressed"
    assert "below watch_threshold" in decision.suppression_reason

def test_low_threshold_alerts():
    config = Config(alert_threshold=0.10, watch_threshold=0.05)
    assert classify_and_decide(BREACH, config).decision == "alert"


def test_confidence_gate_blocks_keyword_heavy_rumor():
    rumor = article(
        "Rumor: unconfirmed breach, ransomware, CVE-2026-1111 actively exploited",
        "breach",
        published=False,
    )
    decision = classify_and_decide(rumor, Config())
    assert decision.decision == "suppressed"
    assert "min_confidence" in decision.suppression_reason

def test_kev_boost_bounded_and_capped():
    import pytest as _pytest
    config = Config()
    results = [ClassifierResult(classifier="vulnerability", score=0.5, label="med"),
               ClassifierResult(classifier="confidence", score=1.0, label="reliable")]
    plain = decide(article("t", "s"), results, config)
    boosted = decide(article("t", "s"), results, config, kev_corroborated=True)
    assert boosted.average_score == _pytest.approx(min(plain.average_score + 0.10, 1.0))
    assert "kev_corroboration +0.10" in boosted.safety_notes

def test_kev_boost_never_bypasses_confidence_gate():
    config = Config()
    results = [ClassifierResult(classifier="vulnerability", score=1.0, label="high"),
               ClassifierResult(classifier="confidence", score=0.1, label="unreliable")]
    boosted = decide(article("t", "s"), results, config, kev_corroborated=True)
    assert boosted.decision == "suppressed"
    assert "min_confidence" in boosted.suppression_reason

def test_recent_vulnerability_plus_active_exploitation_promotes_to_alert():
    results = [
        ClassifierResult(classifier="vulnerability", score=0.5, label="medium"),
        ClassifierResult(classifier="active_attack", score=0.4, label="medium"),
        ClassifierResult(classifier="breach_impact", score=0.0, label="none"),
        ClassifierResult(classifier="confidence", score=1.0, label="reliable",
                         reasons=["recent, substantive, unhedged item"]),
    ]
    decision = decide(article("t", "s"), results, Config())
    assert decision.average_score == 0.4
    assert decision.decision == "alert"
    assert any("active exploitation" in note for note in decision.safety_notes)
    assert build_alert(decision).safety_notes == decision.safety_notes

def test_stale_cross_signal_item_stays_watchlist():
    results = [
        ClassifierResult(classifier="vulnerability", score=0.5, label="medium"),
        ClassifierResult(classifier="active_attack", score=0.4, label="medium"),
        ClassifierResult(classifier="breach_impact", score=0.0, label="none"),
        ClassifierResult(classifier="confidence", score=0.7, label="reliable",
                         reasons=["article older than 14 days"]),
    ]
    decision = decide(article("t", "s"), results, Config())
    assert decision.decision == "watchlist"
    assert not any("promoted" in note for note in decision.safety_notes)

def test_kev_active_watch_item_promotes_to_alert():
    results = [
        ClassifierResult(classifier="vulnerability", score=0.35, label="low"),
        ClassifierResult(classifier="active_attack", score=0.4, label="medium"),
        ClassifierResult(classifier="breach_impact", score=0.0, label="none"),
        ClassifierResult(classifier="confidence", score=1.0, label="reliable",
                         reasons=["recent, substantive, unhedged item"]),
    ]
    decision = decide(article("t", "s"), results, Config(), kev_corroborated=True)
    assert decision.decision == "alert"
    assert "kev_corroboration +0.10" in decision.safety_notes
    assert any("CISA KEV" in note for note in decision.safety_notes)

def test_promotions_respect_operator_watch_threshold():
    results = [
        ClassifierResult(classifier="vulnerability", score=0.5, label="medium"),
        ClassifierResult(classifier="active_attack", score=0.4, label="medium"),
        ClassifierResult(classifier="breach_impact", score=0.0, label="none"),
        ClassifierResult(classifier="confidence", score=1.0, label="reliable",
                         reasons=["recent, substantive, unhedged item"]),
    ]
    config = Config(alert_threshold=0.95, watch_threshold=0.9)
    decision = decide(article("t", "s"), results, config)
    assert decision.decision == "suppressed"
