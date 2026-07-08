"""Configuration validation tests.

These cover defaults, YAML loading, CLI-style overrides, invalid thresholds,
source defaults, and the provider/model requirement for opt-in LLM mode.
"""

import pytest
from pydantic import ValidationError

from newsroom.config import Config, load_config


def test_defaults():
    config = Config()
    assert config.alert_threshold == 0.55
    assert config.watch_threshold == 0.35
    assert config.classifier_weights["confidence"] == 0.5
    assert config.llm.enabled is False


def test_load_yaml_and_override(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("alert_threshold: 0.8\nwatch_threshold: 0.3\n")
    config = load_config(path, alert_threshold=0.9)
    assert config.alert_threshold == 0.9
    assert config.watch_threshold == 0.3


def test_none_overrides_ignored(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("alert_threshold: 0.8\n")
    config = load_config(path, alert_threshold=None)
    assert config.alert_threshold == 0.8


def test_invalid_thresholds_rejected():
    with pytest.raises(ValidationError):
        Config(alert_threshold=0.4, watch_threshold=0.6)
    with pytest.raises(ValidationError):
        Config(alert_threshold=1.5)


def test_source_defaults_and_llm_validation():
    config = Config(sources=[{"name": "Example Source", "url": "https://example.com/feed"}])
    assert config.sources[0].source_id == "example-source"
    assert config.sources[0].type == "rss"

    with pytest.raises(ValidationError):
        Config(llm={"enabled": True})
