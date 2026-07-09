"""CLI entrypoint tests.

These call `newsroom.cli.main` directly with fixture feeds and temp output/DB
paths, so they verify command behavior without live network access.
"""

from newsroom.cli import main


def _run_args(feed, tmp_path):
    return [
        "run",
        "--config", "config.yaml",
        "--fixture", str(feed),
        "--output-dir", str(tmp_path / "out"),
        "--db-path", str(tmp_path / "out" / "newsroom.db"),
        "--no-kev",
    ]


def test_cli_fixture_run(fixture_feed, tmp_path):
    assert main(_run_args(fixture_feed, tmp_path)) == 0


def test_cli_prompt_injection_fixture_run(prompt_injection_feed, tmp_path):
    assert main(_run_args(prompt_injection_feed, tmp_path)) == 0


def test_cli_llm_requires_provider_and_model(tmp_path):
    bad_config = tmp_path / "bad-llm.yaml"
    bad_config.write_text(
        "sources: []\n"
        "llm:\n"
        "  enabled: false\n"
        "  provider:\n"
        "  model:\n"
    )
    assert main(["run", "--config", str(bad_config), "--llm",
                 "--db-path", str(tmp_path / "n.db"), "--no-kev"]) == 2
