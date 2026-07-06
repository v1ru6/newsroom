"""LangGraph workflow wiring the agent-safety pipeline end to end.

fetch_sources -> normalize_untrusted_items -> dedupe_items ->
  deterministic_pre_score -> specialist_agents -> review_agent_outputs ->
  inbound_safety_gates -> write_evidence_ledger -> coordinator_decisions ->
  write_outputs

Each node is a plain function over a shared typed state, so every stage can be
unit-tested without the graph and swapped independently.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from newsroom.agents import run_specialist_agents
from newsroom.alerts import build_alert
from newsroom.config import Config
from newsroom.ingest.rss import articles_to_normalized_items, dedupe_items, fetch_all
from newsroom.llm import run_optional_llm_triage
from newsroom.models import (
    AgentFinding,
    AgentTrace,
    ArticleDecision,
    ClassifierResult,
    EvidenceLedgerEntry,
    GateDecision,
    NewsArticle,
    NormalizedItem,
    RunReport,
    SafetyReport,
    SourceHealth,
    stable_id,
)
from newsroom.outputs import write_outputs
from newsroom.scoring import decide
from newsroom.store import Store
from newsroom.safety import (
    build_safety_report,
    item_gate_decisions,
    redact_untrusted_text,
    review_findings,
)

logger = logging.getLogger(__name__)


class WorkflowState(TypedDict, total=False):
    config: Config
    articles: list[NewsArticle]
    articles_by_id: dict[str, NewsArticle]
    items: list[NormalizedItem]
    item_gates: dict[str, list[GateDecision]]
    findings: list[AgentFinding]
    reviewed_findings: list[AgentFinding]
    gate_decisions: list[GateDecision]
    evidence_ledger: list[EvidenceLedgerEntry]
    safety_report: SafetyReport
    agent_trace: list[AgentTrace]
    source_health: list[SourceHealth]
    duplicates_removed: int
    articles_seen: int
    decisions: list[ArticleDecision]
    report: RunReport
    errors: list[str]
    started_at: datetime
    store: Store
    run_id: int
    new_articles: int
    kev_articles: set[str]
    mentions_by_article: dict[str, dict[str, bool]]


def fetch_sources(state: WorkflowState) -> WorkflowState:
    config = state["config"]
    articles, health = fetch_all(config)
    errors = [f"{h.name}: {h.error}" for h in health if h.error]
    return {
        "articles": articles,
        "articles_by_id": {article.id: article for article in articles},
        "articles_seen": len(articles),
        "source_health": health,
        "errors": state.get("errors", []) + errors,
    }


def normalize_untrusted_items(state: WorkflowState) -> WorkflowState:
    return {"items": articles_to_normalized_items(state["articles"])}


def dedupe_items_node(state: WorkflowState) -> WorkflowState:
    unique, removed = dedupe_items(state["items"])
    # cross-run dedupe: skip items already persisted with an unchanged text
    # hash; a changed hash means updated content, so re-classify.
    known = state["store"].known_text_hashes()
    fresh = [item for item in unique if known.get(item.article_id) != item.text_hash]
    unique_article_ids = {item.article_id for item in fresh}
    return {
        "items": fresh,
        "articles": [
            article for article in state["articles"] if article.id in unique_article_ids
        ],
        "duplicates_removed": removed,
        "new_articles": len(fresh),
    }


def kev_enrichment(state: WorkflowState) -> WorkflowState:
    """Refresh the KEV cache and mark items whose CVEs are known-exploited.

    KEV is corroboration metadata, never articles. Mentions are persisted
    later in persist_state, alongside the articles they refer to.
    """
    from newsroom.ingest.kev import extract_cves, refresh_kev

    config, store = state["config"], state["store"]
    errors = list(state.get("errors", []))
    kev_articles: set[str] = set()
    mentions_by_article: dict[str, dict[str, bool]] = {}
    try:
        refresh_kev(store, config)
        kev_ids = store.kev_ids()
        for item in state["items"]:
            cves = extract_cves(item.untrusted_text)
            if cves:
                mentions = {cve: cve in kev_ids for cve in cves}
                mentions_by_article[item.article_id] = mentions
                if any(mentions.values()):
                    kev_articles.add(item.article_id)
    except Exception as exc:
        logger.exception("KEV enrichment failed")
        errors.append(f"kev_enrichment: {exc}")
    return {"kev_articles": kev_articles,
            "mentions_by_article": mentions_by_article, "errors": errors}


def deterministic_pre_score(state: WorkflowState) -> WorkflowState:
    trace = list(state.get("agent_trace", []))
    trace.append(
        AgentTrace(
            trace_id=stable_id("deterministic_pre_score", str(len(state["items"]))),
            agent_id="pre_score",
            action="deterministic_pre_score",
            status="ok",
            details={"items": len(state["items"])},
        )
    )
    return {"agent_trace": trace}


def specialist_agents(state: WorkflowState) -> WorkflowState:
    config = state["config"]
    errors = list(state.get("errors", []))
    try:
        item_gates = {
            item.id: item_gate_decisions(item, llm_enabled=config.llm.enabled)
            for item in state["items"]
        }
        findings, trace = run_specialist_agents(state["items"], state["articles_by_id"])
        llm_findings, llm_gates, llm_trace = run_optional_llm_triage(
            state["items"], item_gates, config
        )
        findings.extend(llm_findings)
        trace.extend(llm_trace)
        return {
            "item_gates": item_gates,
            "findings": findings,
            "gate_decisions": [gate for gates in item_gates.values() for gate in gates]
            + llm_gates,
            "agent_trace": state.get("agent_trace", []) + trace,
            "errors": errors,
        }
    except Exception as exc:  # one agent-stage failure must be visible
        logger.exception("specialist agent stage failed")
        errors.append(f"specialist_agents: {exc}")
        return {
            "item_gates": {},
            "findings": [],
            "gate_decisions": [],
            "agent_trace": state.get("agent_trace", []),
            "errors": errors,
        }


def review_agent_outputs(state: WorkflowState) -> WorkflowState:
    items_by_id = {item.id: item for item in state["items"]}
    reviewed, review_gates = review_findings(state.get("findings", []), items_by_id)
    return {
        "reviewed_findings": reviewed,
        "gate_decisions": state.get("gate_decisions", []) + review_gates,
    }


def inbound_safety_gates(state: WorkflowState) -> WorkflowState:
    gates = state.get("gate_decisions", [])
    safety_report = build_safety_report(gates, llm_enabled=state["config"].llm.enabled)
    return {"safety_report": safety_report}


def write_evidence_ledger(state: WorkflowState) -> WorkflowState:
    items_by_id = {item.id: item for item in state["items"]}
    gates_by_item: dict[str, list[GateDecision]] = {}
    for gate in state.get("gate_decisions", []):
        if gate.item_id:
            gates_by_item.setdefault(gate.item_id, []).append(gate)

    ledger: list[EvidenceLedgerEntry] = []
    for finding in state.get("reviewed_findings", []):
        item = items_by_id[finding.item_id]
        item_gates = gates_by_item.get(item.id, [])
        non_pass = [gate for gate in item_gates if gate.status != "pass"]
        if any(gate.status == "drop" and gate.finding_id == finding.finding_id for gate in item_gates):
            continue
        gate_status = "pass"
        if any(gate.status == "warn" for gate in non_pass):
            gate_status = "warn"
        if any(gate.status == "llm_blocked" for gate in non_pass):
            gate_status = "llm_blocked"
        categories = sorted({gate.owasp_category for gate in non_pass})
        ledger.append(
            EvidenceLedgerEntry(
                ledger_id=stable_id(finding.finding_id, "ledger"),
                agent_id=finding.agent_id,
                item_id=item.id,
                article_id=item.article_id,
                title=redact_untrusted_text(item.title),
                source_url=item.canonical_url,
                source=item.source,
                source_id=item.source_id,
                trust_level=item.trust_level,
                claim=redact_untrusted_text(finding.claim),
                score=finding.score,
                label=finding.label,
                evidence=[redact_untrusted_text(value) for value in finding.evidence],
                supporting_finding_ids=[finding.finding_id],
                gate_status=gate_status,
                owasp_categories=categories,
                provenance=item.provenance,
            )
        )
    return {"evidence_ledger": ledger}


AGENT_TO_CLASSIFIER = {
    "vulnerability_agent": "vulnerability",
    "campaign_agent": "active_attack",
    "breach_agent": "breach_impact",
    "confidence_agent": "confidence",
}


def coordinator_decisions(state: WorkflowState) -> WorkflowState:
    config = state["config"]
    articles_by_id = state["articles_by_id"]
    ledger_by_item: dict[str, list[EvidenceLedgerEntry]] = {}
    for entry in state.get("evidence_ledger", []):
        ledger_by_item.setdefault(entry.item_id, []).append(entry)

    decisions: list[ArticleDecision] = []
    for item in state["items"]:
        entries = ledger_by_item.get(item.id, [])
        results = [
            ClassifierResult(
                classifier=AGENT_TO_CLASSIFIER[entry.agent_id],
                score=entry.score,
                label=entry.label,
                reasons=[entry.claim],
                evidence=entry.evidence,
            )
            for entry in entries
            if entry.agent_id in AGENT_TO_CLASSIFIER
        ]
        article = articles_by_id[item.article_id]
        kev_articles: set[str] = state.get("kev_articles", set())
        if results:
            decision = decide(article, results, config,
                              kev_corroborated=article.id in kev_articles)
        else:
            decision = ArticleDecision(
                article=article,
                results=[],
                average_score=0.0,
                threshold=config.alert_threshold,
                decision="suppressed",
                suppression_reason="no reviewed ledger entries",
            )
        decision.ledger_entry_ids = [entry.ledger_id for entry in entries]
        decision.owasp_categories = sorted(
            {category for entry in entries for category in entry.owasp_categories}
        )
        if any(entry.gate_status == "llm_blocked" for entry in entries):
            decision.gate_status = "llm_blocked"
        elif any(entry.gate_status == "warn" for entry in entries):
            decision.gate_status = "warn"
        else:
            decision.gate_status = "pass"
        # HITL: an injection-tripwired item that still routes to alert or
        # watchlist needs a human eye before it is trusted.
        decision.review_required = (
            decision.gate_status == "llm_blocked" and decision.decision != "suppressed"
        )
        decisions.append(decision)

    decisions.sort(key=lambda d: d.average_score, reverse=True)
    return {"decisions": decisions}


def route_decisions(state: WorkflowState) -> WorkflowState:
    decisions = state["decisions"]
    report = RunReport(
        started_at=state["started_at"],
        finished_at=datetime.now(timezone.utc),
        source_health=state["source_health"],
        articles_seen=state["articles_seen"],
        duplicates_removed=state["duplicates_removed"],
        alerts=[build_alert(d) for d in decisions if d.decision == "alert"],
        watchlist=[d for d in decisions if d.decision == "watchlist"],
        suppressed=[d for d in decisions if d.decision == "suppressed"],
        errors=state.get("errors", []),
        config_used=state["config"].model_dump(mode="json"),
        evidence_ledger=state.get("evidence_ledger", []),
        safety_report=state.get("safety_report", SafetyReport()),
        agent_trace=state.get("agent_trace", []),
    )
    return {"report": report}


def persist_state(state: WorkflowState) -> WorkflowState:
    store: Store = state["store"]
    run_id = state["run_id"]
    report = state["report"]
    hashes_by_article = {item.article_id: item.text_hash for item in state["items"]}
    for health in state["source_health"]:
        store.record_source_health(run_id, health)
    mentions_by_article = state.get("mentions_by_article", {})
    for decision in state["decisions"]:
        store.upsert_article(decision.article, run_id,
                             text_hash=hashes_by_article.get(decision.article.id, ""))
        store.record_decision(run_id, decision)
        mentions = mentions_by_article.get(decision.article.id)
        if mentions:
            store.record_cve_mentions(decision.article.id, mentions)
    for alert in report.alerts:
        store.record_alert(alert)
    store.finish_run(
        run_id,
        finished_at=report.finished_at,
        articles_seen=state["articles_seen"],
        new_articles=state.get("new_articles", 0),
        duplicates_removed=state["duplicates_removed"],
        alert_count=len(report.alerts),
        watch_count=len(report.watchlist),
        suppressed_count=len(report.suppressed),
        errors=report.errors,
    )
    return {}


def write_outputs_node(state: WorkflowState) -> WorkflowState:
    config = state["config"]
    output_dir = Path(config.output_dir)
    if (
        not state.get("decisions")
        and state.get("new_articles", 0) == 0
        and (output_dir / "run_manifest.json").exists()
    ):
        return {}
    write_outputs(state["report"], state["decisions"], output_dir,
                  kev_articles=state.get("kev_articles", set()))
    return {}


def build_graph():
    graph = StateGraph(WorkflowState)
    graph.add_node("fetch_sources", fetch_sources)
    graph.add_node("normalize_untrusted_items", normalize_untrusted_items)
    graph.add_node("dedupe_items", dedupe_items_node)
    graph.add_node("kev_enrichment", kev_enrichment)
    graph.add_node("deterministic_pre_score", deterministic_pre_score)
    graph.add_node("specialist_agents", specialist_agents)
    graph.add_node("review_agent_outputs", review_agent_outputs)
    graph.add_node("inbound_safety_gates", inbound_safety_gates)
    graph.add_node("write_evidence_ledger", write_evidence_ledger)
    graph.add_node("coordinator_decisions", coordinator_decisions)
    graph.add_node("route_decisions", route_decisions)
    graph.add_node("persist_state", persist_state)
    graph.add_node("write_outputs", write_outputs_node)

    graph.add_edge(START, "fetch_sources")
    graph.add_edge("fetch_sources", "normalize_untrusted_items")
    graph.add_edge("normalize_untrusted_items", "dedupe_items")
    graph.add_edge("dedupe_items", "kev_enrichment")
    graph.add_edge("kev_enrichment", "deterministic_pre_score")
    graph.add_edge("deterministic_pre_score", "specialist_agents")
    graph.add_edge("specialist_agents", "review_agent_outputs")
    graph.add_edge("review_agent_outputs", "inbound_safety_gates")
    graph.add_edge("inbound_safety_gates", "write_evidence_ledger")
    graph.add_edge("write_evidence_ledger", "coordinator_decisions")
    graph.add_edge("coordinator_decisions", "route_decisions")
    graph.add_edge("route_decisions", "persist_state")
    graph.add_edge("persist_state", "write_outputs")
    graph.add_edge("write_outputs", END)
    return graph.compile()


def run_workflow(config: Config, store: Store | None = None) -> RunReport:
    owns_store = store is None
    store = store or Store(config.db_path)
    started_at = datetime.now(timezone.utc)
    run_id = store.begin_run(started_at)
    try:
        app = build_graph()
        final_state = app.invoke(
            {"config": config, "started_at": started_at, "errors": [],
             "store": store, "run_id": run_id}
        )
        return final_state["report"]
    finally:
        if owns_store:
            store.close()
