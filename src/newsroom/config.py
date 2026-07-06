"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator


class SourceConfig(BaseModel):
    name: str
    url: str
    source_id: str | None = None
    type: str = "rss"
    trust_level: str = "medium"
    enabled: bool = True
    stale_after_hours: int | None = None
    focus_tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def default_source_id(self) -> "SourceConfig":
        if self.source_id is None:
            self.source_id = self.name.lower().replace(" ", "-")
        return self


class LLMConfig(BaseModel):
    enabled: bool = False
    provider: str | None = None
    model: str | None = None
    max_items: int = Field(default=5, ge=0)
    timeout_seconds: float = Field(default=20.0, gt=0)
    max_prompt_chars: int = Field(default=4000, ge=500)
    max_retries: int = Field(default=0, ge=0)
    # Spotlighting: how untrusted article text is marked as data inside the
    # prompt. "delimit" wraps it in per-call random-nonce markers, "datamark"
    # interleaves a private-use character between words, "base64" encodes it.
    spotlight_mode: str = Field(default="delimit", pattern="^(delimit|datamark|base64)$")

    @model_validator(mode="after")
    def require_provider_when_enabled(self) -> "LLMConfig":
        if self.enabled and (not self.provider or not self.model):
            raise ValueError("llm.provider and llm.model are required when llm.enabled is true")
        return self


class KEVConfig(BaseModel):
    enabled: bool = True
    url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    refresh_hours: float = Field(default=6.0, gt=0)
    timeout_seconds: float = Field(default=15.0, gt=0)


class Config(BaseModel):
    sources: list[SourceConfig] = Field(default_factory=list)
    # Calibration note: the average spans four orthogonal experts, so even a
    # story that maxes one domain (e.g. a critical zero-day) lands near 0.6.
    # Thresholds are therefore lower than a single-classifier scale would use.
    alert_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
    watch_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    min_confidence: float = Field(default=0.30, ge=0.0, le=1.0)
    classifier_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "vulnerability": 1.0,
            "active_attack": 1.0,
            "breach_impact": 1.0,
            "confidence": 0.5,
        }
    )
    max_items_per_source: int = Field(default=10, ge=1)
    source_timeout_seconds: float = Field(default=10.0, gt=0)
    output_dir: Path = Path("output")
    db_path: Path = Path("output/newsroom.db")
    fixture_path: Path | None = None
    llm: LLMConfig = Field(default_factory=LLMConfig)
    kev: KEVConfig = Field(default_factory=KEVConfig)

    @model_validator(mode="after")
    def check_thresholds(self) -> "Config":
        if self.watch_threshold > self.alert_threshold:
            raise ValueError(
                "watch_threshold must be <= alert_threshold "
                f"({self.watch_threshold} > {self.alert_threshold})"
            )
        for name, weight in self.classifier_weights.items():
            if weight < 0:
                raise ValueError(f"classifier weight for {name!r} must be >= 0")
        return self


def load_config(path: str | Path, **overrides) -> Config:
    """Load YAML config, applying CLI overrides (ignores None values).

    Keys prefixed with a nested section name (llm_, kev_) override inside
    that section, e.g. llm_enabled=True -> raw["llm"]["enabled"] = True.
    """
    raw = yaml.safe_load(Path(path).read_text()) or {}
    for key, value in overrides.items():
        if value is None:
            continue
        for section in ("llm", "kev"):
            if key.startswith(f"{section}_"):
                nested = dict(raw.get(section) or {})
                nested[key.removeprefix(f"{section}_")] = value
                raw[section] = nested
                break
        else:
            raw[key] = value
    return Config.model_validate(raw)
