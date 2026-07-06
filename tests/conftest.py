from pathlib import Path

import pytest

from newsroom.config import Config, KEVConfig

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_feed() -> Path:
    return FIXTURES / "rss_sample.xml"


@pytest.fixture
def prompt_injection_feed() -> Path:
    return FIXTURES / "rss_prompt_injection.xml"


@pytest.fixture
def fixture_config(fixture_feed, tmp_path) -> Config:
    return Config(fixture_path=fixture_feed, output_dir=tmp_path / "output",
                  db_path=tmp_path / "output" / "newsroom.db",
                  kev=KEVConfig(enabled=False))
