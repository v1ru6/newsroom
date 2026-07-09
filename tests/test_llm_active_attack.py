"""LLM-backed active-attack specialist tests.

The specialist builds on the regex expert: regex signals feed the prompt as
trusted context, and every failure mode (provider error, malformed output,
ungrounded evidence, injection-blocked item, spend cap) recovers to the
deterministic regex result.
"""

import json
from datetime import datetime, timezone

import pytest

from newsroom.classifiers.llm_active_attack import LLMActiveAttackClassifier
from newsroom.config import Config, LLMConfig
from newsroom.ingest.rss import articles_to_normalized_items
from newsroom.llm_wire import FakeProvider
from newsroom.models import GateDecision, NewsArticle, stable_id


def make_pair(summary="Researchers observed active exploitation by a ransomware campaign."):
    article = NewsArticle(
        id=stable_id("https://example.com/a"), title="Attack news",
        summary=summary, source="test", source_id="test",
        url="https://example.com/a", published_at=datetime.now(timezone.utc),
    )
    item = articles_to_normalized_items([article])[0]
    return item, article


def llm_config(**llm_overrides) -> Config:
    llm = dict(enabled=True, provider="fake", model="fixture")
    llm.update(llm_overrides)
    return Config(llm=LLMConfig(**llm))


def payload(score=0.9, claim="coordinated intrusion campaign in progress",
            evidence=("active exploitation",)):
    return {"findings": [{"score": score, "label": "high", "claim": claim,
                          "evidence": list(evidence), "source_refs": ["https://example.com/a"]}]}


def classifier(provider, config=None):
    return LLMActiveAttackClassifier(provider=provider, config=config or llm_config())


def test_llm_refines_regex_result():
    item, article = make_pair()
    clf = classifier(FakeProvider(responses={item.id: payload()}))
    result, details = clf.classify_item(item, article, allow_llm=True)

    assert details["mode"] == "llm"
    assert result.classifier == "active_attack"
    assert result.score == 0.9
    assert result.label == "high"
    assert any("coordinated intrusion campaign" in r for r in result.reasons)
    # grounded LLM evidence plus the regex expert's own matches are preserved
    assert "active exploitation" in " ".join(result.evidence).lower()


def test_llm_can_downgrade_a_regex_false_positive():
    # regex fires on "ransomware" in a marketing summary; the LLM says no.
    item, article = make_pair(
        "Vendor webinar: how our product would have stopped last year's ransomware.")
    clf = classifier(FakeProvider(responses={item.id: {"findings": []}}))
    result, details = clf.classify_item(item, article, allow_llm=True)

    assert details["mode"] == "llm"
    assert result.score == 0.0
    assert result.label == "none"


def test_provider_error_falls_back_to_regex():
    item, article = make_pair()
    clf = classifier(FakeProvider(responses={}))  # KeyError for every item
    result, details = clf.classify_item(item, article, allow_llm=True)

    assert details["mode"] == "regex_fallback"
    assert result.score > 0  # deterministic signals still count
    assert any("fallback" in r for r in result.reasons)


def test_provider_error_redacted_and_receives_safety_prompt():
    from newsroom.llm import LLM_SAFETY_SYSTEM_PROMPT

    item, article = make_pair()

    class FailingProvider:
        system_prompt = None

        def generate(self, prompt, *, item_id, system_prompt=None):
            self.system_prompt = system_prompt
            raise RuntimeError("api_key=TESTONLYDUMMYVALUE1234567890")

    provider = FailingProvider()
    clf = classifier(provider)
    result, details = clf.classify_item(item, article, allow_llm=True)
    combined = json.dumps({"result": result.model_dump(mode="json"), "details": details})

    assert provider.system_prompt == LLM_SAFETY_SYSTEM_PROMPT
    assert "TESTONLYDUMMYVALUE1234567890" not in combined
    assert "[REDACTED_SECRET]" in combined


def test_malformed_model_output_falls_back_to_regex():
    item, article = make_pair()
    clf = classifier(FakeProvider(responses={item.id: "not json {{"}))
    result, details = clf.classify_item(item, article, allow_llm=True)
    assert details["mode"] == "regex_fallback"
    assert result.score > 0


def test_ungrounded_llm_evidence_falls_back_to_regex():
    # A hijacked/hallucinating model cannot launder a high score through
    # evidence that is not verbatim in the source text.
    item, article = make_pair()
    clf = classifier(FakeProvider(responses={
        item.id: payload(evidence=["fabricated quote never in the article"])}))
    result, details = clf.classify_item(item, article, allow_llm=True)
    assert details["mode"] == "regex_fallback"
    assert result.score != 0.9


# --- integration through run_specialist_agents ---


def test_specialist_agents_use_llm_for_campaign_agent():
    from newsroom.agents import run_specialist_agents

    item, article = make_pair()
    config = llm_config()
    clf = classifier(FakeProvider(responses={item.id: payload()}), config)
    findings, trace = run_specialist_agents(
        [item], {article.id: article}, config=config,
        item_gates={item.id: []}, active_attack=clf)

    campaign = next(f for f in findings if f.agent_id == "campaign_agent")
    assert campaign.score == 0.9
    assert any(t.agent_id == "campaign_agent" and t.action == "llm_classify"
               and t.details.get("mode") == "llm" for t in trace)
    # the other three experts stay deterministic
    assert {f.agent_id for f in findings} == {
        "vulnerability_agent", "campaign_agent", "breach_agent", "confidence_agent"}


def test_llm_blocked_gate_forces_regex_path():
    from newsroom.agents import run_specialist_agents

    item, article = make_pair()
    config = llm_config()
    blocked_gate = GateDecision(
        gate_id="g1", item_id=item.id, owasp_category="LLM01 Prompt Injection",
        status="llm_blocked", reason="injection tripwire")

    class ExplodingProvider:
        def generate(self, prompt, *, item_id, system_prompt=None):
            raise AssertionError("provider must not be called for blocked items")

    clf = classifier(ExplodingProvider(), config)
    findings, trace = run_specialist_agents(
        [item], {article.id: article}, config=config,
        item_gates={item.id: [blocked_gate]}, active_attack=clf)
    campaign = next(f for f in findings if f.agent_id == "campaign_agent")
    assert campaign.score > 0  # regex result, computed without any LLM call


def test_max_items_counts_failed_llm_attempts():
    from newsroom.agents import run_specialist_agents

    pairs = [make_pair() for _ in range(2)]
    items = []
    articles_by_id = {}
    for index, (item, article) in enumerate(pairs):
        item = item.model_copy(update={"id": f"i{index}", "article_id": f"a{index}"})
        article = article.model_copy(update={"id": f"a{index}"})
        items.append(item)
        articles_by_id[article.id] = article

    class FailingProvider:
        calls = 0

        def generate(self, prompt, *, item_id, system_prompt=None):
            self.calls += 1
            raise RuntimeError("provider unavailable")

    provider = FailingProvider()
    config = llm_config(max_items=1)
    clf = classifier(provider, config)
    findings, trace = run_specialist_agents(
        items, articles_by_id, config=config,
        item_gates={item.id: [] for item in items}, active_attack=clf)

    campaign_traces = [t for t in trace if t.agent_id == "campaign_agent"
                       and t.action == "llm_classify"]
    modes = [t.details.get("mode") for t in campaign_traces]
    assert provider.calls == 1
    assert modes == ["regex_fallback", "regex_capped"]
    assert all(f.score > 0 for f in findings if f.agent_id == "campaign_agent")


# --- end to end through the workflow ---


def test_workflow_active_attack_score_comes_from_llm(fixture_feed, tmp_path):
    from newsroom.config import KEVConfig
    from newsroom.workflow import run_workflow

    responses = tmp_path / "llm_responses.json"
    responses.write_text(json.dumps({"_default": {"findings": [{
        "score": 0.85, "label": "high",
        "claim": "llm specialist confirms campaign activity",
        "evidence": ["active exploitation"],
        "source_refs": ["https://example.com/apt-campaign"],
    }]}}))
    cfg = Config(fixture_path=fixture_feed, output_dir=tmp_path / "o",
                 db_path=tmp_path / "o" / "n.db", kev=KEVConfig(enabled=False),
                 llm=LLMConfig(enabled=True, provider="fake", model="fixture",
                               fixture_path=responses, triage_enabled=False))
    report = run_workflow(cfg)

    campaign_entries = [e for e in report.evidence_ledger
                        if e.agent_id == "campaign_agent"]
    assert campaign_entries
    # the APT item's active-attack score is the LLM's 0.85 (grounded evidence),
    # not the regex composite of 1.0
    apt = [e for e in campaign_entries if "llm specialist" in e.claim]
    assert apt and all(e.score == pytest.approx(0.85) for e in apt)
    # triage disabled: no fifth expert entries
    assert not any(e.agent_id == "llm_triage_agent" for e in report.evidence_ledger)
