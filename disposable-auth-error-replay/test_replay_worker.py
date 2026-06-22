#!/usr/bin/env python3
"""Tests for disposable-auth error replay worker."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import replay_worker


class ErrorProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: D401 - silence test server logs.
        return

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        body = {"ok": True, "path": parsed.path}
        status = 200

        if "'" in params.get("q", [""])[0]:
            status = 500
            body = {
                "error": "SQL syntax error near quote",
                "driver": "PostgreSQL",
            }

        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_safe_get_detects_sql_error_delta():
    server = run_server()
    try:
        request = replay_worker.RequestCase(
            method="GET",
            url=f"http://127.0.0.1:{server.server_port}/search?q=test",
            headers={"User-Agent": "test"},
        )
        decision, mutations, alerts = replay_worker.run_replay(
            request=request,
            mode="safe",
            owned_markers=[],
            authorization="Bearer disposable",
            cookie=None,
            max_probes=2,
            timeout=2.0,
            dry_run=False,
        )
        assert decision.allow is True
        assert len(mutations) == 2
        assert any(alert.family == "sql_orm" and alert.name == "q" for alert in alerts)
    finally:
        server.shutdown()


def test_dangerous_route_blocked_even_with_disposable_mode():
    request = replay_worker.RequestCase(
        method="POST",
        url="https://example.test/billing/refund?id=123",
        headers={"Content-Type": "application/json"},
        body=b'{"reason":"test"}',
    )
    decision = replay_worker.classify_request(request, mode="disposable")
    assert decision.allow is False
    assert decision.reason == "dangerous-route"


def test_owned_resource_allows_stateful_marker():
    request = replay_worker.RequestCase(
        method="POST",
        url="https://example.test/projects/disposable-123/draft",
        headers={"Content-Type": "application/json"},
        body=b'{"title":"test"}',
    )
    decision = replay_worker.classify_request(
        request,
        mode="owned-resource",
        owned_markers=["/projects/disposable-"],
    )
    assert decision.allow is True
    assert decision.reason == "owned-resource"


def test_dry_run_plans_query_mutations_without_network():
    request = replay_worker.RequestCase(
        method="GET",
        url="https://example.test/search?q=test&page=1",
        headers={},
    )
    decision, mutations, alerts = replay_worker.run_replay(
        request=request,
        mode="safe",
        owned_markers=[],
        authorization=None,
        cookie=None,
        max_probes=3,
        timeout=1.0,
        dry_run=True,
    )
    assert decision.allow is True
    assert len(mutations) == 3
    assert alerts == []


if __name__ == "__main__":
    tests = [
        test_safe_get_detects_sql_error_delta,
        test_dangerous_route_blocked_even_with_disposable_mode,
        test_owned_resource_allows_stateful_marker,
        test_dry_run_plans_query_mutations_without_network,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} tests passed")
