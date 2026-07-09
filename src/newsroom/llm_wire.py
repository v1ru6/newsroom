"""LLM provider wiring for the optional triage path.

This is the boundary between run_optional_llm_triage (prompt in, raw JSON
string out) and an actual model backend. FakeProvider replays fixture
responses for offline runs and tests; AnthropicProvider calls the Claude API
with structured outputs. Both return a raw string that still passes through
validate_model_output, so the LLM05 gate is exercised on every path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    import anthropic
    import openai

    from newsroom.config import Config


class LLMProvider(Protocol):
    # item_id lets FakeProvider select the right fixture entry; a real
    # provider ignores it.
    def generate(self, prompt: str, *, item_id: str,
                 system_prompt: str | None = None) -> str: ...


@dataclass
class FakeProvider:
    responses: dict[str, Any]
    default: Any | None = None

    def generate(self, prompt: str, *, item_id: str,
                 system_prompt: str | None = None) -> str:
        if item_id in self.responses:
            value = self.responses[item_id]
        elif self.default is not None:
            value = self.default
        else:
            raise KeyError(f"no fixture response for item {item_id!r} and no default")
        # A str fixture is returned verbatim so tests can inject malformed
        # JSON; dict/list fixtures may be written as natural JSON.
        if isinstance(value, str):
            return value
        return json.dumps(value)

    @classmethod
    def from_file(cls, path: Path) -> "FakeProvider":
        data = json.loads(Path(path).read_text())
        default = data.pop("_default", None)
        return cls(responses=data, default=default)


@dataclass
class AnthropicProvider:
    model: str
    max_tokens: int = 1024
    timeout_seconds: float = 20.0
    max_retries: int = 0
    client: "anthropic.Anthropic | None" = None

    def __post_init__(self) -> None:
        if self.client is None:
            import anthropic

            # Credentials resolve the normal SDK way (ANTHROPIC_API_KEY or an
            # `ant auth login` profile); no key is ever configured here.
            self.client = anthropic.Anthropic(
                timeout=self.timeout_seconds, max_retries=self.max_retries
            )

    def generate(self, prompt: str, *, item_id: str,
                 system_prompt: str | None = None) -> str:
        # Deferred import: llm.py imports build_provider from this module.
        from newsroom.llm import LLMResponsePayload

        # Structured outputs constrain the response to the payload schema;
        # errors (timeouts, rate limits, refusals) propagate to the caller,
        # which fails closed per item.
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "output_format": LLMResponsePayload,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        response = self.client.messages.parse(**kwargs)
        return response.parsed_output.model_dump_json()


@dataclass
class OpenAIProvider:
    model: str
    max_tokens: int = 1024
    timeout_seconds: float = 20.0
    max_retries: int = 0
    client: "openai.OpenAI | None" = None

    def __post_init__(self) -> None:
        if self.client is None:
            import openai

            # Credentials resolve the normal SDK way (OPENAI_API_KEY); no key
            # is ever configured here.
            self.client = openai.OpenAI(
                timeout=self.timeout_seconds, max_retries=self.max_retries
            )

    def generate(self, prompt: str, *, item_id: str,
                 system_prompt: str | None = None) -> str:
        # json_object mode keeps the response parseable across models; strict
        # schema enforcement stays downstream in validate_model_output, which
        # runs for every provider anyway.
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = self.client.chat.completions.create(
            model=self.model,
            max_completion_tokens=self.max_tokens,
            response_format={"type": "json_object"},
            messages=messages,
        )
        return response.choices[0].message.content or ""


def build_provider(config: "Config") -> LLMProvider:
    provider = config.llm.provider
    if provider == "fake":
        if config.llm.fixture_path is not None:
            return FakeProvider.from_file(config.llm.fixture_path)
        return FakeProvider(responses={})
    if provider == "anthropic":
        return AnthropicProvider(
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            timeout_seconds=config.llm.timeout_seconds,
            max_retries=config.llm.max_retries,
        )
    if provider == "openai":
        return OpenAIProvider(
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            timeout_seconds=config.llm.timeout_seconds,
            max_retries=config.llm.max_retries,
        )
    raise ValueError(
        f"unsupported llm.provider {provider!r}; "
        "only 'fake', 'anthropic', and 'openai' are implemented"
    )
