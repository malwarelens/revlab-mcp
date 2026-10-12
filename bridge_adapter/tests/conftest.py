"""Test fixtures: run the real adapter HTTP server (stdlib) on an
ephemeral port with FakeAutomateClient injected, then talk to it over
actual HTTP with urllib — so what gets verified is the full wire
contract, not just handler functions."""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import adapter as adapter_mod  # noqa: E402
from fake_automate import FakeAutomateClient  # noqa: E402


class HttpResult:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload


class BridgeHttpClient:
    def __init__(self, base_url):
        self.base = base_url

    def call(self, method, path, body=None):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return HttpResult(resp.status, json.loads(resp.read()))
        except urllib.error.HTTPError as e:
            return HttpResult(e.code, json.loads(e.read()))

    def get(self, path):
        return self.call("GET", path)

    def post(self, path, body):
        return self.call("POST", path, body)

    def delete(self, path, body):
        return self.call("DELETE", path, body)


def _serve(manager):
    server = adapter_mod.make_server("127.0.0.1", 0, manager)
    port = server.server_address[1]
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, BridgeHttpClient(f"http://127.0.0.1:{port}")


@pytest.fixture()
def fake():
    return FakeAutomateClient()


@pytest.fixture()
def bridge(fake):
    """Spawn-mode bridge backed by one fake client instance."""
    manager = adapter_mod.SessionManager(
        "spawn", spawn_factory=lambda target_exe: fake)
    server, client = _serve(manager)
    yield client, fake
    server.shutdown()


@pytest.fixture()
def remote_bridge(fake):
    """Remote-mode bridge: the fake acts as the pre-connected client."""
    manager = adapter_mod.SessionManager("remote", remote_client=fake)
    server, client = _serve(manager)
    yield client, fake
    server.shutdown()


@pytest.fixture()
def started(bridge):
    """A bridge with a live session on C:\\samples\\sample.exe."""
    client, fake = bridge
    resp = client.post("/session/start", {"path": r"C:\samples\sample.exe"})
    assert resp.status == 200, resp.payload
    return client, fake, resp.payload["session_id"], resp.payload
