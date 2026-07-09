"""Run the deterministic expert panel over normalized untrusted items.

Each agent wraps one classifier and emits an AgentFinding plus trace metadata.
This is the "expert-style classifier" layer from the task, but it deliberately
stays deterministic so article text cannot become instructions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from newsroom.classifiers.active_attack import ActiveAttackClassifier
from newsroom.classifiers.breach_impact import BreachImpactClassifier
from newsroom.classifiers.confidence import ConfidenceClassifier
from newsroom.classifiers.vulnerability import VulnerabilityClassifier
from newsroom.models import (
    AgentFinding,
    AgentTrace,
    ClassifierResult,
    GateDecision,
    NewsArticle,
    NormalizedItem,
    stable_id,
)

if TYPE_CHECKING:
    from newsroom.classifiers.llm_active_attack import LLMActiveAttackClassifier
    from newsroom.config import Config

CLASSIFIER_AGENTS = (
    ("vulnerability_agent", VulnerabilityClassifier()),
    ("campaign_agent", ActiveAttackClassifier()),
    ("breach_agent", BreachImpactClassifier()),
    ("confidence_agent", ConfidenceClassifier()),
)
# Future improvement: a new expert registers here, then gets an optional weight
# in config.yaml so scoring changes stay explicit.

def run_specialist_agents(
    items: list[NormalizedItem],
    articles_by_id: dict[str, NewsArticle],
    config: "Config | None" = None,
    item_gates: dict[str, list[GateDecision]] | None = None,
    active_attack: "LLMActiveAttackClassifier | None" = None,
) -> tuple[list[AgentFinding], list[AgentTrace]]:
    """Run the expert panel. When an LLM-backed active_attack specialist is
    supplied, it takes over the campaign_agent slot (regex signals stay as its
    context and fallback); the other experts remain deterministic."""
    findings: list[AgentFinding] = []
    trace: list[AgentTrace] = []
    llm_budget = config.llm.max_items if config is not None else 0
    llm_used = 0
    for item in items:
        article = articles_by_id[item.article_id]
        for agent_id, classifier in CLASSIFIER_AGENTS:
            result: ClassifierResult
            if agent_id == "campaign_agent" and active_attack is not None:
                blocked = any(
                    gate.status == "llm_blocked"
                    for gate in (item_gates or {}).get(item.id, [])
                )
                capped = llm_used >= llm_budget
                allow_llm = not blocked and not capped
                result, details = active_attack.classify_item(
                    item, article, allow_llm=allow_llm
                )
                if capped and not blocked:
                    details = {"mode": "regex_capped",
                               "reason": "llm.max_items cap reached"}
                if allow_llm:
                    llm_used += 1
                action, extra = "llm_classify", details
            else:
                # Rule-based experts keep this path deterministic and
                # instruction-agnostic.
                result = classifier.classify(article)
                action, extra = "deterministic_classify", {}
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
                    action=action,
                    status="ok",
                    details={"score": round(result.score, 4), "label": result.label,
                             **extra},
                )
            )
    return findings, trace
