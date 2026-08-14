import shutil
import uuid
from pathlib import Path

import pytest

from src.mailbox_store import MailboxStore
from src.proxy_store import ProxyParseError, ProxyStore, parse_proxy_url
from src.settings import Settings
from src.webapp import create_app


class StubCodexManager:
    """The proxy endpoints never touch the scheduler; create_app just needs one."""

    def availability(self):
        return {"available": True, "reason": ""}

    def runtime_config(self):
        return {"driver": "protocol", "auth_source": "local", "sms_provider": "hero", "outlook_fetch_mode": "direct"}

    def list_jobs(self):
        return []

    def pipeline_overview(self):
        return {"id": "", "status": "idle", "active": False, "counts": {}}

    def is_account_active(self, email):
        return False


@pytest.fixture
def workspace_path():
    path = Path(__file__).resolve().parent / f"runtime-proxy-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _settings(path: Path) -> Settings:
    return Settings(
        project_root=Path(__file__).resolve().parents[1],
        data_dir=path / "data",
        log_dir=path / "logs",
        browser_executable=None,
        browser_timeout_seconds=120,
        host="127.0.0.1",
        port=5015,
    )


def _client(workspace_path: Path):
    mailbox = MailboxStore(workspace_path / "data")
    app = create_app(
        _settings(workspace_path),
        mailbox_store=mailbox,
        codex_manager=StubCodexManager(),
    )
    return app.test_client()


def test_parse_accepts_supported_forms():
    full = parse_proxy_url("http://user:p@ss@1.2.3.4:8080")
    # Credentials may contain '@'; only the last one separates host from creds.
    assert full == {
        "scheme": "http",
        "host": "1.2.3.4",
        "port": 8080,
        "username": "user",
        "password": "p@ss",
    }
    assert parse_proxy_url("socks5://10.0.0.1:1080")["scheme"] == "socks5"
    assert parse_proxy_url("https://10.0.0.1:443")["scheme"] == "https"
    # Scheme is optional and defaults to http, for both accepted address forms.
    assert parse_proxy_url("1.2.3.4:9000")["scheme"] == "http"
    bare_auth = parse_proxy_url("bob:secret@1.2.3.4:9000")
    assert (bare_auth["scheme"], bare_auth["username"], bare_auth["password"], bare_auth["port"]) == (
        "http",
        "bob",
        "secret",
        9000,
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://1.2.3.4:8080",
        "socks4://1.2.3.4:1080",
        "1.2.3.4",
        "1.2.3.4:notaport",
        "1.2.3.4:70000",
        "1.2.3.4 :80",
        # Only host:port and user:pass@host:port are accepted — the colon-packed
        # vendor shorthand is not, so it must fail loudly instead of being read
        # as a host with a bogus port.
        "1.2.3.4:9000:bob:secret",
    ],
)
def test_parse_rejects_invalid_lines(value):
    with pytest.raises(ProxyParseError):
        parse_proxy_url(value)


def test_masked_url_hides_credentials_and_host(workspace_path: Path):
    store = ProxyStore(workspace_path / "data")
    store.add_many("http://alice:hunter2@proxy.example.io:8001")
    row = store.state()["proxies"][0]
    assert "alice" not in row["url_masked"]
    assert "hunter2" not in row["url_masked"]
    assert row["url_masked"] == "http://***:***@pro***.example.io:8001"
    assert row["has_auth"] is True
    # The raw record (with credentials) stays server-side for testing/browser use.
    assert store.get_raw(row["id"])["password"] == "hunter2"


def test_add_dedupes_by_endpoint_and_reports_invalid(workspace_path: Path):
    store = ProxyStore(workspace_path / "data")
    first = store.add_many("http://1.1.1.1:8000\nsocks5://2.2.2.2:1080\nnope")
    assert (first["inserted"], first["updated"]) == (2, 0)
    assert len(first["invalid"]) == 1
    again = store.add_many("http://1.1.1.1:8000", label="美国")
    assert (again["inserted"], again["updated"]) == (0, 1)
    assert again["summary"]["total"] == 2
    labelled = next(row for row in again["proxies"] if row["url_masked"].endswith(":8000"))
    assert labelled["label"] == "美国"


def test_round_robin_only_runs_when_pool_and_proxies_are_enabled(workspace_path: Path):
    store = ProxyStore(workspace_path / "data")
    store.add_many("http://1.1.1.1:8001\nhttp://2.2.2.2:8002\nhttp://3.3.3.3:8003")
    # Pool disabled → every account runs direct.
    assert store.next_for_account() is None

    store.set_enabled(True)
    rows = store.state()["proxies"]
    store.set_proxy_enabled(rows[1]["id"], False)
    picked = [store.next_for_account()["host"] for _ in range(4)]
    # Disabled entries are skipped and the cursor wraps around.
    assert picked == ["1.1.1.1", "3.3.3.3", "1.1.1.1", "3.3.3.3"]


def test_cursor_survives_a_restart(workspace_path: Path):
    store = ProxyStore(workspace_path / "data")
    store.add_many("http://1.1.1.1:8001\nhttp://2.2.2.2:8002")
    store.set_enabled(True)
    assert store.next_for_account()["host"] == "1.1.1.1"
    # A fresh instance (new process / restarted backend) continues in order.
    assert ProxyStore(workspace_path / "data").next_for_account()["host"] == "2.2.2.2"


def test_browser_config_passes_the_endpoint_through_unchanged(workspace_path: Path):
    store = ProxyStore(workspace_path / "data")
    store.add_many("socks5://user:pw@9.9.9.9:1080")
    store.set_enabled(True)
    config = ProxyStore.browser_config(store.next_for_account())
    # http/https/socks5 are already chrome.proxy fixed_servers scheme names.
    assert config["scheme"] == "socks5"
    assert (config["host"], config["port"], config["username"], config["password"]) == (
        "9.9.9.9",
        1080,
        "user",
        "pw",
    )
    assert ProxyStore.browser_config(None) is None


def test_api_crud_and_pool_toggle(workspace_path: Path):
    client = _client(workspace_path)

    empty = client.get("/api/proxies").get_json()
    assert empty["ok"] is True and empty["proxies"] == [] and empty["enabled"] is False

    added = client.post("/api/proxies", json={"text": "http://1.1.1.1:8001\nhttp://2.2.2.2:8002"}).get_json()
    assert added["inserted"] == 2
    first_id = added["proxies"][0]["id"]

    toggled = client.post("/api/proxies/enabled", json={"enabled": True}).get_json()
    assert toggled["enabled"] is True
    assert client.post("/api/proxies/enabled", json={"enabled": "yes"}).status_code == 400

    disabled = client.post(f"/api/proxies/{first_id}/enabled", json={"enabled": False}).get_json()
    assert disabled["summary"]["active"] == 1
    assert client.post("/api/proxies/missing/enabled", json={"enabled": True}).status_code == 404

    deleted = client.delete(f"/api/proxies/{first_id}").get_json()
    assert deleted["summary"]["total"] == 1
    assert client.delete(f"/api/proxies/{first_id}").status_code == 404


def test_api_add_rejects_empty_and_reports_invalid_lines(workspace_path: Path):
    client = _client(workspace_path)
    assert client.post("/api/proxies", json={"text": "   "}).status_code == 400
    result = client.post("/api/proxies", json={"text": "http://1.1.1.1:8001\nbroken-line"}).get_json()
    assert result["inserted"] == 1
    assert len(result["invalid"]) == 1
    assert "broken-line" in result["invalid"][0]


def test_api_test_endpoint_records_results(workspace_path: Path, monkeypatch):
    client = _client(workspace_path)
    client.post("/api/proxies", json={"text": "http://1.1.1.1:8001\nhttp://2.2.2.2:8002"})

    def fake_test(records, **_kwargs):
        return [
            {
                "id": record["id"],
                "ok": record["port"] == 8001,
                "ip": "203.0.113.5" if record["port"] == 8001 else "",
                "location": "日本 · 东京都" if record["port"] == 8001 else "",
                "latency_ms": 420 if record["port"] == 8001 else None,
                "message": "" if record["port"] == 8001 else "连接超时",
            }
            for record in records
        ]

    monkeypatch.setattr("src.webapp.test_proxies", fake_test)
    result = client.post("/api/proxies/test", json={}).get_json()
    assert result["tested"] == 2
    ok_row = next(row for row in result["proxies"] if row["status"] == "ok")
    bad_row = next(row for row in result["proxies"] if row["status"] == "failed")
    assert (ok_row["ip"], ok_row["location"], ok_row["latency_ms"]) == ("203.0.113.5", "日本 · 东京都", 420)
    assert bad_row["message"] == "连接超时"
    assert result["summary"]["untested"] == 0
    assert result["summary"]["failed"] == 1


def test_api_test_endpoint_validates_selection(workspace_path: Path):
    client = _client(workspace_path)
    assert client.post("/api/proxies/test", json={}).status_code == 400
    client.post("/api/proxies", json={"text": "http://1.1.1.1:8001"})
    assert client.post("/api/proxies/test", json={"proxy_ids": "nope"}).status_code == 400
    assert client.post("/api/proxies/test", json={"proxy_ids": ["ghost"]}).status_code == 404


def test_credentials_never_reach_the_api_surface(workspace_path: Path):
    client = _client(workspace_path)
    client.post("/api/proxies", json={"text": "http://alice:hunter2@proxy.example.io:8001"})
    body = client.get("/api/proxies").get_data(as_text=True)
    assert "hunter2" not in body and "alice" not in body
