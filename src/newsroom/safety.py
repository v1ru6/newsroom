"""OWASP-inspired gates for untrusted news and optional model output.

The cheap regex gates are not the whole defense; they provide tripwires and
telemetry. The stronger control is structural: raw content stays in the
untrusted plane, claims must be grounded, and only reviewed ledger entries feed
the trusted coordinator.
"""

from __future__ import annotations

import html
import re
import unicodedata
from collections import Counter

from newsroom.models import AgentFinding, GateDecision, NormalizedItem, SafetyReport, stable_id

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


def normalize_text(value: str) -> str:
    """Canonicalize untrusted text before any detection regex runs.

    Detection is telemetry, not a boundary - but the cheap layer should not
    fall to trivial evasions: HTML entities, NFKC homoglyphs/width tricks,
    zero-width splits, and whitespace games are collapsed here.
    """
    text = html.unescape(value)
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return " ".join(text.split())

PROMPT_INJECTION_RE = re.compile(
    r"\b("
    r"ignore (all )?(previous|prior) instructions|"
    r"disregard (all )?(previous|prior) instructions|"
    r"you are now|act as|developer message|system message|"
    r"call this tool|use the browser|send this data|exfiltrate|"
    r"do not follow your policy"
    r")\b",
    re.IGNORECASE,
)

SYSTEM_PROMPT_RE = re.compile(
    r"\b("
    r"reveal (the )?(system|developer) prompt|"
    r"print (the )?(system|developer) prompt|"
    r"show (the )?(system|developer) instructions|"
    r"leak your prompt"
    r")\b",
    re.IGNORECASE,
)

SECRET_RE = re.compile(
    r"("
    r"(?i:api[_-]?key|secret|password|passwd|token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9._/\-]{8,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}"
    r")"
)


def redact_untrusted_text(value: str) -> str:
    """Remove obvious secrets and instruction-like text from display surfaces."""
    redacted = SECRET_RE.sub("[REDACTED_SECRET]", normalize_text(value))
    redacted = PROMPT_INJECTION_RE.sub("[REDACTED_INSTRUCTION]", redacted)
    redacted = SYSTEM_PROMPT_RE.sub("[REDACTED_PROMPT_REQUEST]", redacted)
    return redacted


def item_gate_decisions(item: NormalizedItem, *, llm_enabled: bool) -> list[GateDecision]:
    text = normalize_text(item.untrusted_text)
    decisions: list[GateDecision] = []

    # Gate output is telemetry; containment comes from trusted-plane separation.
    if PROMPT_INJECTION_RE.search(text):
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM01"),
                item_id=item.id,
                owasp_category="LLM01 Prompt Injection",
                status="llm_blocked",
                reason="instruction-like content detected; optional LLM path is blocked for this item",
            )
        )
    else:
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM01"),
                item_id=item.id,
                owasp_category="LLM01 Prompt Injection",
                status="pass",
                reason="no instruction-like content detected",
            )
        )

    if SECRET_RE.search(text):
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM02"),
                item_id=item.id,
                owasp_category="LLM02 Sensitive Information Disclosure",
                status="warn",
                reason="secret-like text was redacted from prompts and display artifacts",
            )
        )
    else:
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM02"),
                item_id=item.id,
                owasp_category="LLM02 Sensitive Information Disclosure",
                status="pass",
                reason="no secret-like text detected",
            )
        )

    if item.trust_level in {"authoritative", "high", "medium", "operator-curated"}:
        supply_status = "pass"
        supply_reason = "enabled source with configured trust metadata"
    else:
        supply_status = "warn"
        supply_reason = "source trust level is low or unknown"
    decisions.append(
        GateDecision(
            gate_id=stable_id(item.id, "LLM03"),
            item_id=item.id,
            owasp_category="LLM03 Supply Chain",
            status=supply_status,
            reason=supply_reason,
        )
    )

    decisions.append(
        GateDecision(
            gate_id=stable_id(item.id, "LLM04"),
            item_id=item.id,
            owasp_category="LLM04 Data and Model Poisoning",
            status="pass",
            reason="raw content cannot update source weights or memory",
        )
    )

    decisions.append(
        GateDecision(
            gate_id=stable_id(item.id, "LLM06"),
            item_id=item.id,
            owasp_category="LLM06 Excessive Agency",
            status="pass",
            reason="optional LLM path has no tools, network, write, or delivery authority",
        )
    )

    if SYSTEM_PROMPT_RE.search(text):
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM07"),
                item_id=item.id,
                owasp_category="LLM07 System Prompt Leakage",
                status="llm_blocked",
                reason="system-prompt disclosure request detected",
            )
        )
    else:
        decisions.append(
            GateDecision(
                gate_id=stable_id(item.id, "LLM07"),
                item_id=item.id,
                owasp_category="LLM07 System Prompt Leakage",
                status="pass",
                reason="no prompt-disclosure request detected",
            )
        )

    decisions.append(
        GateDecision(
            gate_id=stable_id(item.id, "LLM08"),
            item_id=item.id,
            owasp_category="LLM08 Vector and Embedding Weaknesses",
            status="pass",
            reason="no vector store is used in this implementation",
        )
    )
    decisions.append(
        GateDecision(
            gate_id=stable_id(item.id, "LLM10"),
            item_id=item.id,
            owasp_category="LLM10 Unbounded Consumption",
            status="pass",
            reason="per-source limits, LLM item caps, timeouts, and retry limits are configured",
            evidence=[f"llm_enabled={llm_enabled}"],
        )
    )
    return decisions


def review_findings(
    findings: list[AgentFinding],
    items_by_id: dict[str, NormalizedItem],
) -> tuple[list[AgentFinding], list[GateDecision]]:
    """Keep only source-grounded findings for ledger promotion.

    Grounding is verification, not existence: every evidence string must be a
    verbatim substring of the item's normalized text, so a hijacked model call
    cannot launder fabricated claims into the trusted plane. confidence_agent
    evidence is meta-observations and exempt from the substring rule.
    """
    kept: list[AgentFinding] = []
    gates: list[GateDecision] = []
    for finding in findings:
        if finding.score <= 0:
            kept.append(finding)
            continue
        item = items_by_id.get(finding.item_id)
        item_text = normalize_text(item.untrusted_text) if item else ""
        grounded = finding.agent_id == "confidence_agent" or (
            bool(finding.evidence)
            and all(normalize_text(ev) in item_text for ev in finding.evidence)
        )
        # Do not promote claims that cannot be tied back to source evidence.
        if finding.source_refs and grounded:
            gates.append(
                GateDecision(
                    gate_id=stable_id(finding.finding_id, "LLM09"),
                    item_id=finding.item_id,
                    finding_id=finding.finding_id,
                    owasp_category="LLM09 Misinformation",
                    status="pass",
                    reason="claim is grounded in verbatim source evidence",
                )
            )
            kept.append(finding)
            continue
        reason = (
            "evidence not grounded in source text"
            if finding.source_refs
            else "unsupported claim rejected before evidence-ledger promotion"
        )
        gates.append(
            GateDecision(
                gate_id=stable_id(finding.finding_id, "LLM09"),
                item_id=finding.item_id,
                finding_id=finding.finding_id,
                owasp_category="LLM09 Misinformation",
                status="drop",
                reason=reason,
            )
        )
    return kept, gates


def build_safety_report(
    gates: list[GateDecision], *, llm_enabled: bool
) -> SafetyReport:
    counts = Counter(decision.status for decision in gates)
    llm_blocked_items = sorted(
        {
            decision.item_id
            for decision in gates
            if decision.status == "llm_blocked" and decision.item_id
        }
    )
    return SafetyReport(
        gate_decisions=gates,
        counts=dict(counts),
        llm_enabled=llm_enabled,
        llm_blocked_items=llm_blocked_items,
    )
