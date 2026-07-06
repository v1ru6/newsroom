"""Deterministic specialist agents for the untrusted analysis plane."""

from __future__ import annotations

from newsroom.classifiers.active_attack import ActiveAttackClassifier
from newsroom.classifiers.breach_impact import BreachImpactClassifier
from newsroom.classifiers.confidence import ConfidenceClassifier
from newsroom.classifiers.vulnerability import VulnerabilityClassifier
from newsroom.models import AgentFinding, AgentTrace, NewsArticle, NormalizedItem, stable_id

CLASSIFIER_AGENTS = (
    ("vulnerability_agent", VulnerabilityClassifier()),
    ("campaign_agent", ActiveAttackClassifier()),
    ("breach_agent", BreachImpactClassifier()),
    ("confidence_agent", ConfidenceClassifier()),
)


def run_specialist_agents(
    items: list[NormalizedItem], articles_by_id: dict[str, NewsArticle]
) -> tuple[list[AgentFinding], list[AgentTrace]]:
    findings: list[AgentFinding] = []
    trace: list[AgentTrace] = []
    for item in items:
        article = articles_by_id[item.article_id]
        for agent_id, classifier in CLASSIFIER_AGENTS:
            result = classifier.classify(article)
            claim = "; ".join(result.reasons) if result.reasons else f"{result.label} signal"
            finding = AgentFinding(
                finding_id=stable_id(item.id, agent_id),
                agent_id=agent_id,
                item_id=item.id,
                article_id=item.article_id,
                score=result.score,
                label=result.label,
                claim=claim,
                reasons=result.reasons,
                evidence=result.evidence,
                source_refs=[item.canonical_url],
                supported=True,
            )
            findings.append(finding)
            trace.append(
                AgentTrace(
                    trace_id=stable_id(finding.finding_id, "trace"),
                    agent_id=agent_id,
                    item_id=item.id,
                    action="deterministic_classify",
                    status="ok",
                    details={"score": round(result.score, 4), "label": result.label},
                )
            )
    return findings, trace
