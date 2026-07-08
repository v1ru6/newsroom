"""Classifier abstractions.

Each classifier is an independent "expert": it declares an objective, scans an
article, and returns a 0-1 score with the evidence that produced it. New
experts (including LLM-backed ones) only need to implement `classify`.
"""

from __future__ import annotations
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from newsroom.models import ClassifierResult, NewsArticle

class Classifier(ABC):
    name: str
    objective: str

    @abstractmethod
    def classify(self, article: NewsArticle) -> ClassifierResult:
        ...

@dataclass(frozen=True)
class Signal:
    """A keyword/pattern signal and the score weight it contributes."""

    pattern: str
    weight: float
    reason: str

    def matches(self, text: str) -> list[str]:
        return [m.group(0) for m in re.finditer(self.pattern, text, flags=re.IGNORECASE)]


class KeywordClassifier(Classifier):
    """Deterministic expert scoring by weighted signal hits, capped at 1.0."""

    signals: list[Signal] = []
    # Future improvement: most new experts can start by declaring Signal rows
    # here in a subclass, then graduate to custom classify logic if needed.

    def classify(self, article: NewsArticle) -> ClassifierResult:
        score = 0.0
        reasons: list[str] = []
        evidence: list[str] = []
        for signal in self.signals:
            hits = signal.matches(article.text)
            if hits:
                # Preserve the matched phrase so later stages can ground the score.
                score += signal.weight
                reasons.append(signal.reason)
                evidence.extend(dict.fromkeys(hits[:3]))
        score = min(score, 1.0)
        return ClassifierResult(
            classifier=self.name,
            score=score,
            label=self.label_for(score),
            reasons=reasons,
            evidence=evidence,
        )

    @staticmethod
    def label_for(score: float) -> str:
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        if score > 0.0:
            return "low"
        return "none"
