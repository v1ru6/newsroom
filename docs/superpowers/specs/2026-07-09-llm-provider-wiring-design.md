# LLM Provider Wiring (Fake Provider) — Design

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

## Goal

Wire `run_optional_llm_triage` to actually call a provider, and make that fully testable offline
with a fixture-driven fake provider — no API key required. A real provider (e.g. Anthropic) is a
documented future extension, not part of this change.

## Architecture

- `src/newsroom/llm.py` — unchanged responsibilities: `build_llm_prompt`, `validate_model_output`.
  `run_optional_llm_triage` is updated to call a provider and gains an optional `provider` param.
- `src/newsroom/llm_wire.py` — **new file**, relocated out of `classifiers/` (deleting
  `classifiers/llm_wire.py`) since it holds provider wiring, not a `Classifier`. Contains the
  `LLMProvider` protocol, `FakeProvider`, and the `build_provider` factory.
- `src/newsroom/config.py` — `LLMConfig` gains `fixture_path: Path | None = None`.

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

### `build_provider(config) -> LLMProvider` (`llm_wire.py`)

- `config.llm.provider == "fake"` → `FakeProvider.from_file(config.llm.fixture_path)` if set,
  else `FakeProvider(responses={})`.
- Anything else → `ValueError(f"unsupported llm.provider {config.llm.provider!r}; only 'fake' is implemented, real providers are a future extension")`.
- `config.llm.provider` stays an unconstrained `str | None` (no pydantic pattern) — three existing
  tests in `tests/test_injection_defense.py` construct `LLMConfig(provider="mock", ...)` purely to
  test `build_llm_prompt`, and must keep working untouched.

### `run_optional_llm_triage` (`llm.py`)

Signature becomes:

```python
def run_optional_llm_triage(
    items: list[NormalizedItem],
    item_gates: dict[str, list[GateDecision]],
    config: Config,
    provider: LLMProvider | None = None,
) -> tuple[list[AgentFinding], list[GateDecision], list[AgentTrace]]:
```

`provider` defaults to `build_provider(config)` when not supplied, so `workflow.py`'s call site
needs no changes. Tests can inject a `FakeProvider` directly, bypassing config/fixture files
entirely.

## Data flow

For each allowed item (existing gating/cap logic unchanged):

1. `prompt = build_llm_prompt(item, config)` (unchanged)
2. `raw = provider.generate(prompt, item_id=item.id)`
3. On success: `validate_model_output(raw, item)` (unchanged) → appends findings + pass/drop LLM05
   gates as it already does today.
4. On `provider.generate` raising: append `AgentTrace(status="error", details={"reason": str(exc)})`
   and `GateDecision(status="drop", reason=f"provider call failed: {exc}")` for that item only —
   processing continues for the remaining items ("fail-closed per item", matching the existing
   comment in the file).

## Error handling

- Per-item provider failures never abort the batch (see above).
- `build_provider` raising for an unsupported `provider` name propagates out of
  `run_optional_llm_triage` and is caught by `workflow.py`'s existing broad `try/except` in
  `specialist_agents`, which already converts any stage exception into a visible `errors` entry.
  No new exception handling is needed in `workflow.py`.

## Testing

New `tests/test_llm_wire.py`:

- `FakeProvider.generate`: dict fixture → valid JSON out; string fixture → passed through verbatim
  (malformed-JSON case); missing id with `default` set → default used; missing id with no default
  → raises `KeyError`.
- `FakeProvider.from_file` loads a fixture file correctly, including `_default`.
- `build_provider("fake")` returns a working `FakeProvider`; unsupported provider name raises
  `ValueError`.
- `run_optional_llm_triage` end-to-end with an injected `FakeProvider`:
  - valid finding fixture → `AgentFinding` produced + pass gate + `ok` trace
  - one item's provider call fails (fixture missing, no default) → drop gate + error trace for
    that item only; other items unaffected
  - malformed JSON response → drop gate via existing `validate_model_output`, no crash

## Out of scope

- A real `AnthropicProvider` (or any live network-calling provider). `config.llm.timeout_seconds`
  and `config.llm.max_retries` remain unused until a real provider is added — they exist in
  `LLMConfig` already for that future work.
- Any change to the four deterministic `Classifier` experts or `agents.py`.
