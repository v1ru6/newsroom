"""Turn above-threshold decisions into client-facing threat alerts."""

from __future__ import annotations

from newsroom.models import ArticleDecision, ThreatAlert, stable_id
from newsroom.safety import redact_untrusted_text


def severity_for(score: float) -> str:
    # Bands match the compressed averaged scale (see Config calibration note):
    # >=0.70 means several expert domains fired at once.
    if score >= 0.70:
        return "critical"
    if score >= 0.60:
        return "high"
    return "medium"


def build_alert(decision: ArticleDecision) -> ThreatAlert:
    article = decision.article
    top_reasons = [
        reason
        for result in decision.results
        if result.classifier != "confidence" and result.score > 0
        for reason in result.reasons
    ]
    evidence = sorted(
        {redact_untrusted_text(item) for result in decision.results for item in result.evidence}
    )
    why = redact_untrusted_text(
        "; ".join(top_reasons[:4]) or "aggregate score above alert threshold"
    )
    return ThreatAlert(
        alert_id=stable_id(article.url, "alert"),
        title=redact_untrusted_text(article.title),
        severity=severity_for(decision.average_score),
        score=decision.average_score,
        why_it_matters=why,
        source_url=article.url,
        source=article.source,
        evidence=evidence,
        recommended_action=(
            "Review the source article, confirm exposure of affected products or "
            "data, and notify impacted clients if relevant."
        ),
        ledger_entry_ids=decision.ledger_entry_ids,
        owasp_categories=decision.owasp_categories,
        safety_notes=decision.safety_notes,
        gate_status=decision.gate_status,
        review_status="pending" if decision.review_required else "auto",
    )
