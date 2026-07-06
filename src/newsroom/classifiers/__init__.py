"""Expert classifier registry. Add a classifier here to include it in runs."""

from newsroom.classifiers.active_attack import ActiveAttackClassifier
from newsroom.classifiers.base import Classifier
from newsroom.classifiers.breach_impact import BreachImpactClassifier
from newsroom.classifiers.confidence import ConfidenceClassifier
from newsroom.classifiers.vulnerability import VulnerabilityClassifier


def default_classifiers() -> list[Classifier]:
    return [
        VulnerabilityClassifier(),
        ActiveAttackClassifier(),
        BreachImpactClassifier(),
        ConfidenceClassifier(),
    ]
