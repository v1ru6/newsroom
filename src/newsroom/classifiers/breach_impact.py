"""Expert: data exposure and client-impacting breach stories."""

from newsroom.classifiers.base import KeywordClassifier, Signal


class BreachImpactClassifier(KeywordClassifier):
    name = "breach_impact"
    objective = "Detect data breaches and exposure with client impact."

    signals = [
        Signal(r"\b(data )?breach(ed)?\b", 0.35, "data breach reported"),
        Signal(r"\bleak(ed|s)?\b|\bexposed\b", 0.25, "data leaked or exposed"),
        Signal(r"\bstolen\b|\bexfiltrat", 0.20, "data theft"),
        Signal(r"customer data|patient records|personal (?:data|information)|\bPII\b", 0.25, "personal/customer data affected"),
        Signal(r"\bcredential(s)?\b|password(s)? (?:leaked|stolen|dumped)", 0.20, "credentials involved"),
        Signal(r"\b\d+(?:\.\d+)?\s*(?:million|billion|thousand)\b", 0.15, "large-scale impact figure"),
    ]
