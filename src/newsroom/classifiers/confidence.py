"""Expert: how much should we trust this item at all?

Unlike the topical experts, this one scores article *quality*: thin summaries,
missing dates, and vague hedging reduce the score. Its result participates in
the weighted average (low weight) and also feeds the min_confidence
suppression gate, so a keyword-heavy but unverifiable item cannot alert.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from newsroom.classifiers.base import Classifier
from newsroom.models import ClassifierResult, NewsArticle

HEDGING = re.compile(r"\b(rumor|unconfirmed|allegedly|possible|may have|unnamed)\b", re.IGNORECASE)


class ConfidenceClassifier(Classifier):
    name = "confidence"
    objective = "Penalize thin, stale, or unverifiable items."

    def classify(self, article: NewsArticle) -> ClassifierResult:
        score = 1.0
        reasons: list[str] = []

        if len(article.summary) < 80:
            score -= 0.4
            reasons.append("summary too thin to verify")
        if article.published_at is None:
            score -= 0.2
            reasons.append("no publication date")
        elif datetime.now(timezone.utc) - article.published_at > timedelta(days=14):
            score -= 0.3
            reasons.append("article older than 14 days")
        if HEDGING.search(article.text):
            score -= 0.3
            reasons.append("hedged or unconfirmed language")

        score = max(score, 0.0)
        if not reasons:
            reasons.append("recent, substantive, unhedged item")
        return ClassifierResult(
            classifier=self.name,
            score=score,
            label="reliable" if score >= 0.7 else "uncertain" if score >= 0.4 else "unreliable",
            reasons=reasons,
        )
