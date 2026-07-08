"""Coordinator decision policy: average scores, promotions, and routing.

This is where expert outputs become the task's required average score and final
route: alert, watchlist, or suppressed. Promotions handle cyber-specific cases
where a conservative weighted average would understate urgency.
"""

from __future__ import annotations

from newsroom.config import Config
from newsroom.models import ArticleDecision, ClassifierResult, NewsArticle


def weighted_average(results: list[ClassifierResult], weights: dict[str, float]) -> float:
    """Average of classifier scores, weighted per config. Unknown classifiers
    default to weight 1.0 so newly added experts count immediately."""
    # Collapse the expert signals into the configured routing score.
    total = 0.0
    weight_sum = 0.0
    for result in results:
        weight = weights.get(result.classifier, 1.0)
        total += result.score * weight
        weight_sum += weight
    return total / weight_sum if weight_sum else 0.0


def _result(results: list[ClassifierResult], name: str) -> ClassifierResult | None:
    return next((result for result in results if result.classifier == name), None)


def _score(results: list[ClassifierResult], name: str) -> float:
    result = _result(results, name)
    return result.score if result else 0.0


def _is_current(confidence: ClassifierResult | None) -> bool:
    if confidence is None:
        return True
    joined = " ".join(confidence.reasons).lower()
    stale_markers = ("older than 14 days", "no publication date", "summary too thin")
    return confidence.score >= 0.7 and not any(marker in joined for marker in stale_markers)


def promotion_reason(
    results: list[ClassifierResult],
    *,
    average: float,
    config: Config,
    kev_corroborated: bool,
) -> str | None:
    """Escalate high-signal, current items that average scoring underweights.

    The weighted average is intentionally conservative, but cyber operators
    expect certain cross-signal combinations to alert even when one expert is
    quiet. Promotions still require watch-level aggregate signal and a current,
    substantive item, so stale research posts do not page someone.
    """
    # Promotion rules explain alerts that land below the numeric threshold.
    # Future improvement: urgency rules such as "ransomware is always high"
    # should be modeled here and covered by a focused scoring test.
    if average < config.watch_threshold:
        return None
    confidence = _result(results, "confidence")
    if not _is_current(confidence):
        return None

    vulnerability = _score(results, "vulnerability")
    active_attack = _score(results, "active_attack")
    breach_impact = _score(results, "breach_impact")

    if kev_corroborated and (vulnerability >= 0.35 or active_attack >= 0.4):
        return "promoted: CISA KEV corroboration plus live vulnerability/attack signal"
    if vulnerability >= 0.5 and active_attack >= 0.4:
        return "promoted: vulnerability signal plus active exploitation"
    if active_attack >= 0.55 and breach_impact >= 0.5:
        return "promoted: ransomware/campaign signal plus breach impact"
    return None


def decide(article: NewsArticle, results: list[ClassifierResult], config: Config,
           kev_corroborated: bool = False) -> ArticleDecision:
    average = weighted_average(results, config.classifier_weights)
    safety_notes: list[str] = []
    if kev_corroborated:
        # Single flat corroboration boost, capped; adjusts score only -
        # routing and the confidence gate below are unchanged.
        average = min(average + 0.10, 1.0)
        safety_notes.append("kev_corroboration +0.10")
    confidence = next(
        (r.score for r in results if r.classifier == "confidence"), 1.0
    )

    decision = "suppressed"
    suppression_reason: str | None = None

    # Confidence gates keep keyword-heavy but weakly grounded items out.
    if confidence < config.min_confidence:
        suppression_reason = (
            f"confidence {confidence:.2f} below min_confidence {config.min_confidence:.2f}"
        )
    elif average >= config.alert_threshold:
        decision = "alert"
    elif reason := promotion_reason(
        results, average=average, config=config, kev_corroborated=kev_corroborated
    ):
        decision = "alert"
        safety_notes.append(reason)
    elif average >= config.watch_threshold:
        decision = "watchlist"
    else:
        suppression_reason = (
            f"average {average:.2f} below watch_threshold {config.watch_threshold:.2f}"
        )

    return ArticleDecision(
        article=article,
        results=results,
        average_score=round(average, 4),
        threshold=config.alert_threshold,
        decision=decision,
        suppression_reason=suppression_reason,
        safety_notes=safety_notes,
    )
