# LLM Provider Wiring & Scoring Integration — Design

## Problem

`run_optional_llm_triage` in [`src/newsroom/llm.py`](../../../src/newsroom/llm.py) already builds prompts
(`build_llm_prompt`) and validates model output (`validate_model_output`), but never calls a
provider — it always logs `status="provider_not_implemented"`. There is no way to exercise the
full LLM triage path (prompt → call → validate → findings/gates) end-to-end without a real API
key.

`src/newsroom/classifiers/llm_wire.py` exists as an unused stub (imports `KeywordClassifier`,
`Signal`, does nothing). It doesn't fit the `Classifier` interface used by the four deterministic
experts in `agents.py` — the LLM path is a separate pipeline entirely, feeding
`AgentFinding`/`GateDecision` via `run_optional_llm_triage`, not `ClassifierResult` via
`Classifier.classify`.

More importantly: even once a provider is wired up, LLM findings are structurally invisible to
the alert/watchlist/suppressed decision. `coordinator_decisions` in
[`src/newsroom/workflow.py`](../../../src/newsroom/workflow.py) only rehydrates `ClassifierResult`s
for the four regex agents via `AGENT_TO_CLASSIFIER`, so `weighted_average` never sees the LLM's
opinion — it only affects gate status (`llm_blocked`/`warn`), never the routing score. The LLM
also only ever sees raw article text, never the regex experts' own findings, so it can't act as a
second opinion on what they found.

## Goal

Wire `run_optional_llm_triage` to call a real provider (Anthropic, via structured outputs) with a
fixture-driven `FakeProvider` for offline testing, **and** make the LLM's assessment actually
count: it becomes a fifth weighted expert in the scoring average, and it sees the regex experts'
findings as context so it can corroborate or contradict them rather than reasoning over the
article in isolation.

## Architecture

- `src/newsroom/llm.py` — `build_llm_prompt` gains a prior-signals context block;
  `run_optional_llm_triage` gains a `deterministic_findings` parameter and an optional `provider`
  parameter (defaults to `build_provider(config)`).
- `src/newsroom/llm_wire.py` — **new file**, relocated out of `classifiers/` (deleting
  `classifiers/llm_wire.py`) since it holds provider wiring, not a `Classifier`. Contains the
  `LLMProvider` protocol, `FakeProvider`, `AnthropicProvider`, and the `build_provider` factory.
- `src/newsroom/config.py` — `LLMConfig` gains `max_tokens: int = 1024` (response cap for the real
  provider). `fixture_path` already exists as a top-level `Config` field (not nested under `llm`) —
  `build_provider` reads it from there as `config.fixture_path`, matching existing code rather than
  the original spec's assumption that it would be added under `LLMConfig`.
- `src/newsroom/workflow.py` — `AGENT_TO_CLASSIFIER` gains an `llm_triage_agent` entry;
  `coordinator_decisions` aggregates multiple same-item ledger entries per classifier by max
  score instead of assuming one entry per classifier per item.
- `pyproject.toml` — adds the `anthropic` SDK dependency.

## Components

### `LLMProvider` protocol (`llm_wire.py`)

```python
class LLMProvider(Protocol):
    def generate(self, prompt: str, *, item_id: str) -> str: ...
```

`item_id` is included even though a real provider would ignore it, because `FakeProvider` needs
it to select the right fixture entry (and it's useful for future request tracing/correlation).

### `FakeProvider` (`llm_wire.py`)

```python
@dataclass
class FakeProvider:
    responses: dict[str, Any]
    default: Any | None = None

    def generate(self, prompt: str, *, item_id: str) -> str: ...

    @classmethod
    def from_file(cls, path: Path) -> "FakeProvider": ...
```

- If `responses[item_id]` (or `default`) is a `str`, return it verbatim — lets a fixture inject
  deliberately malformed JSON to exercise `validate_model_output`'s error/drop path.
- If it's a `dict`/`list`, `json.dumps` it — lets fixtures be written as natural JSON matching
  `LLMResponsePayload`.
- If `item_id` is missing and no `default` is set, raise `KeyError`.
- `from_file(path)` loads a JSON file shaped like:
  ```json
  {"item-id-1": {"findings": [...]}, "_default": {"findings": []}}
  ```
  (`_default` populates `default`; every other key populates `responses`.)

### `AnthropicProvider` (`llm_wire.py`)

```python
@dataclass
class AnthropicProvider:
    model: str
    max_tokens: int = 1024
    timeout_seconds: float = 20.0
    max_retries: int = 0
    client: "anthropic.Anthropic | None" = None

    def __post_init__(self) -> None: ...  # constructs a default client if none injected

    def generate(self, prompt: str, *, item_id: str) -> str: ...
```

- `client` is dependency-injectable for tests; when not supplied, `__post_init__` constructs
  `anthropic.Anthropic(timeout=self.timeout_seconds, max_retries=self.max_retries)`, which
  resolves credentials the normal SDK way (`ANTHROPIC_API_KEY` env var or an `ant auth login`
  profile) — no hardcoded key.
- `generate` calls `self.client.messages.parse(model=self.model, max_tokens=self.max_tokens,
  output_format=LLMResponsePayload, messages=[{"role": "user", "content": prompt}])` and returns
  `response.parsed_output.model_dump_json()`. `LLMResponsePayload` is imported from `newsroom.llm`
  **inside** this method (not at module top) to avoid a circular import between `llm.py` (which
  imports `build_provider` from `llm_wire.py`) and `llm_wire.py`.
- Structured outputs (`output_format`) guarantee schema-valid JSON from the API itself. The
  returned string still passes through `validate_model_output` on the way back into
  `run_optional_llm_triage` — redundant in the success case, but keeps `FakeProvider` and
  `AnthropicProvider` on identical downstream paths and keeps the LLM05 gate a real check rather
  than a formality that real traffic never exercises.
- `item_id` is unused by `AnthropicProvider` (each call is a single independent request) but kept
  in the signature to satisfy `LLMProvider`.
- Exceptions from `client.messages.parse` (timeouts, rate limits, refusals, connection errors)
  propagate out of `generate` uncaught — `run_optional_llm_triage`'s existing per-item try/except
  converts them into a `drop` gate + `error` trace for that item only, so no new error handling is
  needed here.

### `build_provider(config) -> LLMProvider` (`llm_wire.py`)

- `config.llm.provider == "fake"` → `FakeProvider.from_file(config.fixture_path)` if set,
  else `FakeProvider(responses={})`.
- `config.llm.provider == "anthropic"` → `AnthropicProvider(model=config.llm.model,
  max_tokens=config.llm.max_tokens, timeout_seconds=config.llm.timeout_seconds,
  max_retries=config.llm.max_retries)`.
- Anything else → `ValueError(f"unsupported llm.provider {config.llm.provider!r}; only 'fake' and 'anthropic' are implemented")`.
- `config.llm.provider` stays an unconstrained `str | None` (no pydantic pattern) — three existing
  tests in `tests/test_injection_defense.py` construct `LLMConfig(provider="mock", ...)` purely to
  test `build_llm_prompt`, and must keep working untouched.

### `LLMResponsePayload` / `LLMFindingPayload` (`llm.py`, unchanged location)

`LLMFindingPayload.label` changes from a free `str` to `Literal["high", "medium", "low", "none"]`
— matching `KeywordClassifier.label_for`'s output so the ledger and dashboard render LLM findings
consistently with the four regex experts, and so the label is enum-constrainable by structured
outputs.

### `build_llm_prompt` (`llm.py`)

Gains a prior-signals context block built from the four regex experts' `AgentFinding`s for that
item (already computed earlier in the `specialist_agents` node, just not previously threaded
through). Format: one line per classifier — `classifier=score(label): reason1; reason2`. Only
`reasons` (developer-authored static strings from each `Signal` definition, e.g. "mentions of CVE
identifiers") are included, never `evidence` (raw matched article substrings — untrusted, and
already spotlighted separately in the existing untrusted-text section of the prompt). Scores are
floats. None of this new block needs spotlighting, since none of it is attacker-influenced.

### `run_optional_llm_triage` (`llm.py`)

Signature becomes:

```python
def run_optional_llm_triage(
    items: list[NormalizedItem],
    item_gates: dict[str, list[GateDecision]],
    config: Config,
    deterministic_findings: list[AgentFinding] | None = None,
    provider: LLMProvider | None = None,
) -> tuple[list[AgentFinding], list[GateDecision], list[AgentTrace]]:
```

`deterministic_findings` is the output of `run_specialist_agents`, passed through by
`specialist_agents` in `workflow.py` (already computed before this call in that node — no new
computation needed, just threading it through). `provider` defaults to `build_provider(config)`
when not supplied, so `workflow.py`'s call site needs only the new `deterministic_findings` arg,
not a `provider` override. Tests can inject a `FakeProvider` directly, bypassing config/fixture
files entirely.

## Data flow

For each allowed item (existing gating/cap logic unchanged):

1. `prompt = build_llm_prompt(item, config, prior_findings=[f for f in deterministic_findings if f.item_id == item.id])`
2. `raw = provider.generate(prompt, item_id=item.id)`
3. On success: `validate_model_output(raw, item)` (unchanged) → appends findings + pass/drop LLM05
   gates as it already does today.
4. On `provider.generate` raising: append `AgentTrace(status="error", details={"reason": str(exc)})`
   and `GateDecision(status="drop", reason=f"provider call failed: {exc}")` for that item only —
   processing continues for the remaining items ("fail-closed per item", matching the existing
   comment in the file).

## Scoring integration

This is the part that makes the LLM's opinion actually reach the dashboard.

- `workflow.py`'s `AGENT_TO_CLASSIFIER` gains `"llm_triage_agent": "llm_triage"`. `weighted_average`
  in `scoring.py` already defaults unknown classifiers to weight `1.0` (existing extension point,
  called out in `agents.py`'s "Future improvement" comment), so `llm_triage` participates in the
  routing average immediately with no config change required. Operators can tune
  `classifier_weights.llm_triage` in `config.yaml` afterward to calibrate its influence.
- **Multi-finding aggregation.** `LLMResponsePayload.findings` is a list — unlike the four regex
  experts (always exactly one `ClassifierResult` per item), the LLM can report multiple concerns
  for one article. Left unhandled, that would create multiple `llm_triage`-classifier ledger
  entries for the same item and over-weight it in `weighted_average` (each entry counted
  separately at weight 1.0). Fix in `coordinator_decisions`: group ledger entries by
  `(item_id, classifier)` and keep only the max-score entry per group before building the
  `ClassifierResult` list. This is a no-op for the four regex agents (always one entry per
  classifier per item already) and only changes behavior for `llm_triage`. All findings still
  reach the evidence ledger for the dashboard — only the scoring input is deduplicated.
- `promotion_reason()` (the cross-signal escalation logic in `scoring.py`) is **not** touched by
  this change — see Out of scope.

## Error handling

- Per-item provider failures never abort the batch (see Data flow, point 4).
- `build_provider` raising for an unsupported `provider` name propagates out of
  `run_optional_llm_triage` and is caught by `workflow.py`'s existing broad `try/except` in
  `specialist_agents`, which already converts any stage exception into a visible `errors` entry.
  No new exception handling is needed in `workflow.py`.
- Cost control for the real provider is `config.llm.max_items` (already exists, defaults to 5) —
  the primary lever for bounding per-run Anthropic API spend. No new cap is introduced; operators
  should keep this conservative when first enabling `provider: anthropic`.

## Testing

New `tests/test_llm_wire.py`:

- `FakeProvider.generate`: dict fixture → valid JSON out; string fixture → passed through verbatim
  (malformed-JSON case); missing id with `default` set → default used; missing id with no default
  → raises `KeyError`.
- `FakeProvider.from_file` loads a fixture file correctly, including `_default`.
- `AnthropicProvider.generate`: inject a stub client (duck-typed `.messages.parse`) — verify the
  call receives the expected `model`/`max_tokens`/`output_format`/`messages`; verify a raised
  exception from the stub client propagates unswallowed out of `generate`.
- `build_provider("fake")` / `build_provider("anthropic")` each return a working provider instance
  of the right type; unsupported provider name raises `ValueError`.
- `run_optional_llm_triage` end-to-end with an injected `FakeProvider`:
  - valid finding fixture → `AgentFinding` produced + pass gate + `ok` trace
  - one item's provider call fails (fixture missing, no default) → drop gate + error trace for
    that item only; other items unaffected
  - malformed JSON response → drop gate via existing `validate_model_output`, no crash

Updated `tests/test_injection_defense.py` (the existing home of `build_llm_prompt` tests):

- `build_llm_prompt` with `prior_findings` passed includes each classifier's score/label/reason
  line; confirms raw `evidence` strings are absent from the rendered prompt.

Updated `tests/test_workflow.py` / `tests/test_scoring.py`:

- Two ledger entries for the same item both with `agent_id="llm_triage_agent"` → only the
  max-score one is rehydrated into `weighted_average`'s input.
- `llm_triage` participates in `weighted_average` with the default weight of `1.0` when
  `classifier_weights` doesn't mention it; an explicit `classifier_weights.llm_triage` override is
  respected.
- One end-to-end test: a `FakeProvider` fixture whose returned score is high enough that, blended
  with the regex scores via `weighted_average`, moves an item from `watchlist` to `alert`.

## Out of scope

- Extending `promotion_reason()` (`scoring.py`) to reference LLM findings directly (e.g. "LLM
  corroboration plus live vulnerability signal always alerts", mirroring the existing
  `kev_corroborated` promotion rule). Flagged as a natural follow-on, not bundled into this change.
- Calibrating the default `classifier_weights.llm_triage` value against real-world traffic — ships
  at the implicit default of `1.0` (via the existing unknown-classifier fallback), tunable by the
  operator in `config.yaml`.
- Any provider besides `fake` and `anthropic` (Bedrock/Vertex/Foundry/etc.) — a documented future
  extension via the same `build_provider` dispatch.
- Any change to the four deterministic `Classifier` experts themselves (`agents.py`,
  `classifiers/*.py`) beyond how their output is aggregated in `coordinator_decisions`.
