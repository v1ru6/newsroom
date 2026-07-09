"""Provider-agnostic authentication command tests.

`newsroom auth login <provider>` launches the provider's sanctioned sign-in
(browser link flow for Anthropic via the ant CLI, guided key setup for
OpenAI); `newsroom auth status` verifies each provider with a cheap call.
Network verification is stubbed here - live checks are manual.
"""

import pytest

from newsroom import auth
from newsroom.cli import main


# --- login ---


def test_login_anthropic_runs_ant_link_flow(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(auth.shutil, "which", lambda name: "/opt/homebrew/bin/ant")
    monkeypatch.setattr(auth.subprocess, "call", lambda argv: calls.append(argv) or 0)
    monkeypatch.setitem(auth.CHECKS, "anthropic", lambda: (False, "no credentials"))

    assert auth.login("anthropic") == 0
    assert calls == [["ant", "auth", "login"]]


def test_login_anthropic_without_ant_prints_install_hint(monkeypatch, capsys):
    monkeypatch.setattr(auth.shutil, "which", lambda name: None)
    monkeypatch.setitem(auth.CHECKS, "anthropic", lambda: (False, "no credentials"))

    assert auth.login("anthropic") == 1
    out = capsys.readouterr().out
    assert "brew install anthropics/tap/ant" in out


def test_login_openai_already_authenticated(monkeypatch, capsys):
    monkeypatch.setitem(auth.CHECKS, "openai", lambda: (True, "authenticated"))
    assert auth.login("openai") == 0
    assert "already authenticated" in capsys.readouterr().out


def test_login_openai_prints_key_guidance(monkeypatch, capsys):
    monkeypatch.setitem(auth.CHECKS, "openai", lambda: (False, "no credentials"))
    assert auth.login("openai") == 1
    out = capsys.readouterr().out
    assert "OPENAI_API_KEY" in out
    assert "platform.openai.com" in out


# --- status ---


def test_status_reports_each_provider(monkeypatch, capsys):
    monkeypatch.setitem(auth.CHECKS, "anthropic", lambda: (True, "authenticated as x"))
    monkeypatch.setitem(auth.CHECKS, "openai", lambda: (False, "OPENAI_API_KEY not set"))

    assert auth.status() == 0  # at least one provider works
    out = capsys.readouterr().out
    assert "anthropic" in out and "ok" in out
    assert "openai" in out and "OPENAI_API_KEY not set" in out


def test_status_all_providers_failing_is_nonzero(monkeypatch):
    monkeypatch.setitem(auth.CHECKS, "anthropic", lambda: (False, "nope"))
    monkeypatch.setitem(auth.CHECKS, "openai", lambda: (False, "nope"))
    assert auth.status() == 1


# --- CLI wiring ---


def test_cli_auth_login_routes_to_provider(monkeypatch):
    seen = []
    monkeypatch.setattr("newsroom.auth.login", lambda provider: seen.append(provider) or 0)
    assert main(["auth", "login", "openai"]) == 0
    assert seen == ["openai"]


def test_cli_auth_rejects_unknown_provider():
    with pytest.raises(SystemExit):
        main(["auth", "login", "codex-cli-token"])
