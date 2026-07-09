"""Provider-agnostic authentication for the LLM providers.

`newsroom auth login <provider>` launches each vendor's sanctioned sign-in:

- anthropic: browser link flow via `ant auth login` (OAuth/PKCE against your
  existing Anthropic account - approve the link and you're authenticated; the
  SDK reads the resulting profile automatically, no key handling in NewsRoom).
- openai: guided API-key setup. OpenAI's "Sign in with ChatGPT" subscription
  flow is only available to apps approved into their pilot program, so the
  generally available path for API access is an API key.

No credential is ever stored by NewsRoom itself - the vendor SDKs resolve
credentials from their own profiles/environment at call time.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Callable


def check_anthropic() -> tuple[bool, str]:
    try:
        import anthropic

        client = anthropic.Anthropic(timeout=10.0, max_retries=0)
        client.messages.count_tokens(  # free endpoint, proves auth end to end
            model="claude-opus-4-8",
            messages=[{"role": "user", "content": "ping"}],
        )
        return True, "credentials valid (SDK profile or ANTHROPIC_API_KEY)"
    except Exception as exc:
        return False, f"not authenticated: {exc}"


def check_openai() -> tuple[bool, str]:
    import os

    if not os.environ.get("OPENAI_API_KEY"):
        return False, "OPENAI_API_KEY not set"
    try:
        import openai

        client = openai.OpenAI(timeout=10.0, max_retries=0)
        client.models.list()  # cheap metadata call, proves the key works
        return True, "OPENAI_API_KEY valid"
    except Exception as exc:
        return False, f"not authenticated: {exc}"


CHECKS: dict[str, Callable[[], tuple[bool, str]]] = {
    "anthropic": check_anthropic,
    "openai": check_openai,
}

PROVIDERS = tuple(CHECKS)


def login(provider: str) -> int:
    ok, message = CHECKS[provider]()
    if ok:
        print(f"{provider}: already authenticated - {message}")
        return 0

    if provider == "anthropic":
        if shutil.which("ant"):
            print("Opening the Anthropic sign-in link in your browser; "
                  "approve it with your existing account...")
            code = subprocess.call(["ant", "auth", "login"])
            if code == 0:
                print("anthropic: authenticated. `newsroom run` will pick the "
                      "profile up automatically.")
            return code
        print(
            "The Anthropic link sign-in needs the ant CLI:\n"
            "  brew install anthropics/tap/ant\n"
            "  newsroom auth login anthropic   # opens the browser link\n"
            "Alternatively export ANTHROPIC_API_KEY from console.anthropic.com."
        )
        return 1

    # openai
    print(
        "OpenAI has no generally available link sign-in for API access\n"
        "(ChatGPT-subscription sign-in is limited to apps in OpenAI's pilot).\n"
        "Create a key at https://platform.openai.com/api-keys and export it:\n"
        "  export OPENAI_API_KEY=sk-...\n"
        "then re-run: newsroom auth status openai"
    )
    return 1


def status(provider: str | None = None) -> int:
    providers = [provider] if provider else list(PROVIDERS)
    any_ok = False
    for name in providers:
        ok, message = CHECKS[name]()
        any_ok = any_ok or ok
        print(f"{name:10} {'ok' if ok else '--'}  {message}")
    return 0 if any_ok else 1
