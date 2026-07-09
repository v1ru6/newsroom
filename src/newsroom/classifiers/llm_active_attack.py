"""LLM-backed active-attack specialist.

Owns the "active_attack" expert slot when the LLM is enabled. The regex
ActiveAttackClassifier still runs first: its signals are handed to the model
as trusted context ("build on top of the regexes"), and its result is the
recovery path for every failure mode - provider errors, malformed output,
ungrounded evidence, injection-blocked items, and the spend cap. The pipeline
therefore never scores worse than the deterministic baseline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from newsroom.classifiers.active_attack import ActiveAttackClassifier
from newsroom.classifiers.base import KeywordClassifier
from newsroom.models import ClassifierResult, NewsArticle, NormalizedItem
from newsroom.safety import normalize_text, redact_untrusted_text, safe_error_message

if TYPE_CHECKING:
    from newsroom.config import Config
    from newsroom.llm_wire import LLMProvider


class LLMActiveAttackClassifier:
    """Specialized agent: regex signals in, model judgement out, regex fallback."""

    name = "active_attack"
    objective = (
        "Assess active exploitation, campaigns, and threat-actor activity, "
        "refining the deterministic keyword signals."
    )

    def __init__(self, provider: "LLMProvider", config: "Config",
                 base: ActiveAttackClassifier | None = None):
        self.provider = provider
        self.config = config
        self.base = base or ActiveAttackClassifier()

    def build_prompt(self, item: NormalizedItem, prior: ClassifierResult) -> str:
        from newsroom.llm import spotlight

        safe_text = redact_untrusted_text(item.untrusted_text)
        safe_text = safe_text[: self.config.llm.max_prompt_chars]
        wrapped, spotlight_instruction = spotlight(safe_text, self.config.llm.spotlight_mode)
        if prior.reasons:
            signals = "; ".join(
                f"{reason}" for reason in prior.reasons
            ) + f" (composite regex score {prior.score:.2f})"
        else:
            signals = "none matched"
        return (
            "You are the NewsRoom active-attack expert. Assess ONLY evidence of "
            "attacks in progress: active exploitation, campaigns, APT/state-sponsored "
            "activity, ransomware, malware, botnets, phishing. Ignore other threat "
            "dimensions (vulnerability severity, breach impact, source quality). "
            "Return strict JSON matching {\"findings\":[{\"score\":0.0,\"label\":\"...\","
            "\"claim\":\"...\",\"evidence\":[],\"source_refs\":[]}]} - at most one finding; "
            "an empty findings list means no active-attack activity. score is your "
            "0-1 judgement of attack activity; every evidence string must be quoted "
            "verbatim from the source text. "
            f"{spotlight_instruction} "
            f"item_id={item.id} source_id={item.source_id} url={item.canonical_url}\n"
            "Deterministic keyword signals for this item (trusted context; the "
            f"regexes are brittle, so refine them): {signals}\n"
            f"source_text:\n{wrapped}"
        )

    def classify_item(
        self, item: NormalizedItem, article: NewsArticle, *, allow_llm: bool
    ) -> tuple[ClassifierResult, dict]:
        base_result = self.base.classify(article)
        if not allow_llm:
            return base_result, {"mode": "regex_blocked",
                                 "reason": "llm blocked or capped for this item"}

        try:
            from newsroom.llm import LLM_SAFETY_SYSTEM_PROMPT

            raw = self.provider.generate(
                self.build_prompt(item, base_result), item_id=item.id,
                system_prompt=LLM_SAFETY_SYSTEM_PROMPT,
            )
            refined = self._refine(raw, item, base_result)
        except Exception as exc:  # recover: the deterministic expert still scores
            reason = safe_error_message(exc)
            fallback = base_result.model_copy(
                update={"reasons": base_result.reasons
                        + [f"llm unavailable, regex fallback: {reason}"]}
            )
            return fallback, {"mode": "regex_fallback", "reason": reason}
        if refined is None:
            fallback = base_result.model_copy(
                update={"reasons": base_result.reasons
                        + ["llm evidence not grounded, regex fallback"]}
            )
            return fallback, {"mode": "regex_fallback",
                              "reason": "llm evidence not grounded in source text"}
        return refined, {"mode": "llm"}

    def _refine(
        self, raw: str, item: NormalizedItem, base_result: ClassifierResult
    ) -> ClassifierResult | None:
        """Turn validated model output into a ClassifierResult, or None when the
        score cannot be grounded (caller falls back to regex)."""
        from newsroom.llm import LLMResponsePayload

        payload = LLMResponsePayload.model_validate_json(raw)
        if not payload.findings:
            # An explicit "nothing here" is a legitimate expert opinion - the
            # model may downgrade a brittle regex false positive.
            return ClassifierResult(
                classifier=self.name, score=0.0, label="none",
                reasons=["llm: no active-attack activity identified"], evidence=[],
            )
        best = max(payload.findings, key=lambda finding: finding.score)
        item_text = normalize_text(item.untrusted_text)
        grounded = [ev for ev in best.evidence if normalize_text(ev) in item_text]
        # A positive model score must be backed by the model's OWN verbatim
        # quotes - regex matches cannot vouch for a claim the model invented.
        if best.score > 0 and not grounded:
            return None
        # Regex matches are appended afterwards so the ledger entry stays rich.
        evidence = list(dict.fromkeys(grounded + base_result.evidence))
        return ClassifierResult(
            classifier=self.name,
            score=best.score,
            label=KeywordClassifier.label_for(best.score),
            reasons=[f"llm: {best.claim}"],
            evidence=evidence,
        )
