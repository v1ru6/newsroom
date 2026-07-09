"""Typed handoff contracts for the whole workflow.

These Pydantic models are the objects that cross stage boundaries: raw news
articles, normalized untrusted items, agent findings, gate decisions, ledger
entries, coordinator decisions, alerts, source health, and run reports.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

_WORD_RE = re.compile(r"[a-z0-9]+")


def normalize_title(title: str) -> str:
    """Collapse a title to a comparable key for near-duplicate detection."""
    return " ".join(_WORD_RE.findall(title.lower()))


def stable_id(*parts: str) -> str:
    """Deterministic short id so re-runs produce diffable output."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


class NewsArticle(BaseModel):
    id: str
    title: str
    summary: str = ""
    source: str
    source_id: str | None = None
    source_type: str = "rss"
    trust_level: str = "medium"
    url: str
    published_at: datetime | None = None
    authors: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    focus_tags: list[str] = Field(default_factory=list)
    untrusted: bool = True

    @property
    def dedupe_keys(self) -> tuple[str, str]:
        return (self.url.rstrip("/").lower(), normalize_title(self.title))

    @property
    def text(self) -> str:
        """The text classifiers evaluate."""
        return f"{self.title}\n{self.summary}"


class ClassifierResult(BaseModel):
    classifier: str
    score: float = Field(ge=0.0, le=1.0)
    label: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class ArticleDecision(BaseModel):
    article: NewsArticle
    results: list[ClassifierResult]
    average_score: float
    threshold: float
    decision: str  # "alert" | "watchlist" | "suppressed"
    suppression_reason: str | None = None
    ledger_entry_ids: list[str] = Field(default_factory=list)
    gate_status: str = "pass"
    owasp_categories: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    # HITL: injection-tripwired items that still route to alert/watchlist are
    # flagged for human review instead of being trusted silently.
    review_required: bool = False


class ThreatAlert(BaseModel):
    alert_id: str
    title: str
    severity: str  # "critical" | "high" | "medium"
    score: float
    why_it_matters: str
    source_url: str
    source: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ledger_entry_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    gate_status: str = "pass"
    review_status: str = "auto"  # "auto" | "pending" | "approved" | "dismissed"


class SourceHealth(BaseModel):
    name: str
    url: str
    status: str  # "ok" | "error" | "empty" | "fixture"
    source_id: str | None = None
    source_type: str = "rss"
    trust_level: str = "medium"
    items_fetched: int = 0
    items_normalized: int = 0
    error: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stale: bool = False


class NormalizedItem(BaseModel):
    id: str
    article_id: str
    title: str
    source: str
    source_id: str
    source_type: str
    trust_level: str
    canonical_url: str
    normalized_title: str
    untrusted_text: str
    text_hash: str
    published_at: datetime | None = None
    focus_tags: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @property
    def dedupe_keys(self) -> tuple[str, str, str]:
        return (
            self.canonical_url.rstrip("/").lower(),
            self.normalized_title,
            self.text_hash,
        )


class AgentFinding(BaseModel):
    finding_id: str
    agent_id: str
    item_id: str
    article_id: str
    score: float = Field(ge=0.0, le=1.0)
    label: str
    claim: str
    reasons: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    owasp_flags: list[str] = Field(default_factory=list)
    supported: bool = True


class GateDecision(BaseModel):
    gate_id: str
    item_id: str | None = None
    finding_id: str | None = None
    owasp_category: str
    status: str  # "pass" | "warn" | "drop" | "llm_blocked"
    reason: str
    evidence: list[str] = Field(default_factory=list)


class EvidenceLedgerEntry(BaseModel):
    ledger_id: str
    agent_id: str
    item_id: str
    article_id: str
    title: str
    source_url: str
    source: str
    source_id: str
    trust_level: str
    claim: str
    score: float = Field(ge=0.0, le=1.0)
    label: str
    evidence: list[str] = Field(default_factory=list)
    supporting_finding_ids: list[str] = Field(default_factory=list)
    gate_status: str = "pass"
    owasp_categories: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CoordinatorDecision(BaseModel):
    item_id: str
    article_id: str
    decision: str
    score: float
    ledger_entry_ids: list[str] = Field(default_factory=list)
    reason: str


class AgentTrace(BaseModel):
    trace_id: str
    agent_id: str
    item_id: str | None = None
    action: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SafetyReport(BaseModel):
    gate_decisions: list[GateDecision] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    llm_enabled: bool = False
    llm_blocked_items: list[str] = Field(default_factory=list)


class RunReport(BaseModel):
    started_at: datetime
    finished_at: datetime | None = None
    source_health: list[SourceHealth] = Field(default_factory=list)
    articles_seen: int = 0
    duplicates_removed: int = 0
    alerts: list[ThreatAlert] = Field(default_factory=list)
    watchlist: list[ArticleDecision] = Field(default_factory=list)
    suppressed: list[ArticleDecision] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    config_used: dict = Field(default_factory=dict)
    evidence_ledger: list[EvidenceLedgerEntry] = Field(default_factory=list)
    safety_report: SafetyReport = Field(default_factory=SafetyReport)
    agent_trace: list[AgentTrace] = Field(default_factory=list)
