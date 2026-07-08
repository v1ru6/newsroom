"""Loopback HTTP server: static monitor console + read-only JSON API.

Every string leaving the API passes redact_untrusted_text; the frontend
additionally renders via textContent only. CSP default-src 'self'.
"""

from __future__ import annotations

import json
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from newsroom.safety import redact_untrusted_text
from newsroom.store import Store

WEB_DIR = Path(__file__).parent / "web"
_CONTENT_TYPES = {".html": "text/html; charset=utf-8",
                  ".css": "text/css; charset=utf-8",
                  ".js": "application/javascript; charset=utf-8"}


def _redact(value):
    if isinstance(value, str):
        return redact_untrusted_text(value)
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    return value


class ApiHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, store: Store, web_dir: Path, **kwargs):
        self.store = store
        self.web_dir = web_dir
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _headers(self, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _json(self, payload, status: int = 200) -> None:
        self._headers(status, "application/json")
        # Treat API responses as an output boundary and redact before serialization.
        self.wfile.write(json.dumps(_redact(payload), default=str).encode())

    def do_GET(self):  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        route = parsed.path
        try:
            if route.startswith("/api/"):
                return self._api(route, query)
            return self._static(route)
        except Exception as exc:
            return self._json({"error": str(exc)}, status=500)

    def do_POST(self):  # noqa: N802 (stdlib naming)
        # Cross-site defense: a browser page on another origin can fire a POST
        # at 127.0.0.1 but cannot attach this custom header without a CORS
        # preflight, which this server never grants.
        if self.headers.get("X-NewsRoom") != "review":
            return self._json({"error": "missing X-NewsRoom header"}, status=403)
        parts = urlparse(self.path).path.strip("/").split("/")
        # expected: api/alerts/<alert_id>/review
        if len(parts) == 4 and parts[:2] == ["api", "alerts"] and parts[3] == "review":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                action = payload.get("action")
                if action not in {"approved", "dismissed"}:
                    return self._json({"error": "action must be approved|dismissed"},
                                      status=400)
                if not self.store.set_alert_review(parts[2], action):
                    return self._json({"error": "unknown alert"}, status=404)
                return self._json({"alert_id": parts[2], "review_status": action})
            except (ValueError, json.JSONDecodeError) as exc:
                return self._json({"error": str(exc)}, status=400)
        return self._json({"error": "not found"}, status=404)

    def _api(self, route: str, q: dict) -> None:
        limit = min(int(q.get("limit", 100)), 500)
        # Future improvement: add a new dashboard panel by adding one Store
        # query here and rendering it in web/app.js through this redacted API.
        if route == "/api/summary":
            return self._json(self.store.summary(include_fixture=False))
        if route == "/api/alerts":
            return self._json(self.store.recent_alerts(
                limit=limit, include_fixture=False))
        if route == "/api/decisions":
            return self._json(self.store.search_decisions(
                q=q.get("q"), decision=q.get("decision"), limit=limit,
                include_fixture=False))
        if route == "/api/timeline":
            return self._json(self.store.timeline(
                days=min(int(q.get("days", 7)), 90), include_fixture=False))
        if route == "/api/sources":
            return self._json(self.store.latest_source_health(include_fixture=False))
        if route == "/api/kev":
            return self._json(self.store.recent_kev(limit=limit))
        if route == "/api/runs":
            return self._json(self.store.recent_runs(limit=limit))
        return self._json({"error": "not found"}, status=404)

    def _static(self, route: str) -> None:
        name = "index.html" if route == "/" else route.lstrip("/")
        target = (self.web_dir / name).resolve()
        # Keep static serving local, with traversal blocked and content types fixed.
        if (self.web_dir.resolve() not in target.parents
                or target.suffix not in _CONTENT_TYPES or not target.is_file()):
            return self._json({"error": "not found"}, status=404)
        self._headers(200, _CONTENT_TYPES[target.suffix])
        self.wfile.write(target.read_bytes())


def create_server(store: Store, port: int = 8765,
                  web_dir: Path | None = None) -> ThreadingHTTPServer:
    handler = partial(ApiHandler, store=store, web_dir=web_dir or WEB_DIR)
    return ThreadingHTTPServer(("127.0.0.1", port), handler)
