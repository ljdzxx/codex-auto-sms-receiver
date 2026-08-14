import shutil
import uuid
from pathlib import Path

import pytest

from src.browser_config_store import (
    BrowserConfigStore,
    _known_timezones,
    navigate_bridge_timeout_ms,
    page_action_bridge_timeout_ms,
)
from src.mailbox_store import MailboxStore
from src.settings import Settings
from src.webapp import create_app


class StubCodexManager:
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
    path = Path(__file__).resolve().parent / f"runtime-bcfg-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _client(workspace_path: Path):
    settings = Settings(
        project_root=Path(__file__).resolve().parents[1],
        data_dir=workspace_path / "data",
        log_dir=workspace_path / "logs",
        browser_executable=None,
        browser_timeout_seconds=120,
        host="127.0.0.1",
        port=5015,
    )
    app = create_app(
        settings,
        mailbox_store=MailboxStore(workspace_path / "data"),
        codex_manager=StubCodexManager(),
    )
    return app.test_client()


def test_defaults_match_the_previously_hardcoded_values(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    assert store.get() == {"page_load_timeout_ms": 45_000, "element_wait_timeout_ms": 30_000}


def test_save_rejects_out_of_range_and_non_numeric(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    with pytest.raises(ValueError, match="页面加载超时"):
        store.save({"page_load_timeout_ms": 1_000})
    with pytest.raises(ValueError, match="元素等待超时"):
        store.save({"element_wait_timeout_ms": 999_000})
    with pytest.raises(ValueError, match="必须是数字"):
        store.save({"page_load_timeout_ms": "abc"})
    # A rejected save leaves the stored values untouched.
    assert store.get()["page_load_timeout_ms"] == 45_000


def test_save_keeps_unspecified_keys_and_survives_a_restart(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    store.save({"element_wait_timeout_ms": 90_000})
    assert store.get() == {"page_load_timeout_ms": 45_000, "element_wait_timeout_ms": 90_000}
    assert BrowserConfigStore(workspace_path / "data").get()["element_wait_timeout_ms"] == 90_000


def test_corrupt_file_falls_back_to_defaults(workspace_path: Path):
    data_dir = workspace_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / BrowserConfigStore.FILENAME).write_text("{not json", encoding="utf-8")
    assert BrowserConfigStore(data_dir).get()["page_load_timeout_ms"] == 45_000


@pytest.mark.parametrize("element_wait_ms", [5_000, 30_000, 120_000, 300_000])
def test_backend_budget_always_outlives_the_browser(element_wait_ms):
    # CLAUDE.md 踩坑 #2: if both ends expire together the job is orphaned. The
    # backend budget must stay ahead no matter what the user configures — and
    # submit_email can spend the element budget up to three times in one call.
    values = {"page_load_timeout_ms": 300_000, "element_wait_timeout_ms": element_wait_ms}
    assert navigate_bridge_timeout_ms(values) > values["page_load_timeout_ms"]
    assert page_action_bridge_timeout_ms(values) > element_wait_ms * 3


def test_api_round_trip_and_validation(workspace_path: Path):
    client = _client(workspace_path)

    initial = client.get("/api/browser-config").get_json()["config"]
    assert initial["page_load_timeout_ms"] == 45_000
    assert initial["defaults"]["element_wait_timeout_ms"] == 30_000
    assert initial["bounds"]["page_load_timeout_ms"] == {"min": 10_000, "max": 300_000}
    assert initial["derived"]["navigate_bridge_timeout_ms"] == 90_000

    saved = client.post(
        "/api/browser-config",
        json={"page_load_timeout_ms": 90_000, "element_wait_timeout_ms": 60_000},
    ).get_json()["config"]
    assert (saved["page_load_timeout_ms"], saved["element_wait_timeout_ms"]) == (90_000, 60_000)
    assert saved["derived"]["navigate_bridge_timeout_ms"] == 135_000
    assert saved["derived"]["page_action_bridge_timeout_ms"] == 240_000

    rejected = client.post("/api/browser-config", json={"page_load_timeout_ms": 5})
    assert rejected.status_code == 400
    assert "页面加载超时" in rejected.get_json()["error"]
    # The rejected request must not have changed anything.
    assert client.get("/api/browser-config").get_json()["config"]["page_load_timeout_ms"] == 90_000


def test_fingerprint_defaults_to_off(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    assert store.fingerprint() == {"enabled": False, "timezone": "", "language": ""}


def test_fingerprint_round_trip_and_does_not_disturb_the_timeouts(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    store.save({"element_wait_timeout_ms": 60_000})
    store.save({"fingerprint": {"enabled": True, "timezone": "Asia/Tokyo", "language": "en-US"}})

    assert store.fingerprint() == {"enabled": True, "timezone": "Asia/Tokyo", "language": "en-US"}
    # Saving one section must not reset the other, in either direction.
    assert store.get()["element_wait_timeout_ms"] == 60_000
    store.save({"page_load_timeout_ms": 50_000})
    assert store.fingerprint()["timezone"] == "Asia/Tokyo"
    # Survives a restart, and is exposed to the side panel.
    reopened = BrowserConfigStore(workspace_path / "data")
    assert reopened.public()["fingerprint"]["language"] == "en-US"


def test_fingerprint_rejects_bad_values_without_writing_anything(workspace_path: Path):
    store = BrowserConfigStore(workspace_path / "data")
    store.save({"fingerprint": {"enabled": True, "timezone": "Europe/Berlin", "language": "de-DE"}})

    with pytest.raises(ValueError, match="时区格式不正确"):
        store.save({"fingerprint": {"enabled": True, "timezone": "not a zone!", "language": "en-US"}})
    with pytest.raises(ValueError, match="语言标签格式不正确"):
        store.save({"fingerprint": {"enabled": True, "timezone": "Asia/Tokyo", "language": "英语"}})
    # Enabling with a blank field would override with nothing at all.
    with pytest.raises(ValueError, match="必须同时填写"):
        store.save({"fingerprint": {"enabled": True, "timezone": "Asia/Tokyo", "language": ""}})
    with pytest.raises(ValueError, match="必须是数字"):
        store.save({"page_load_timeout_ms": "abc", "fingerprint": {"enabled": False, "timezone": "", "language": ""}})

    assert store.fingerprint() == {"enabled": True, "timezone": "Europe/Berlin", "language": "de-DE"}


def test_fingerprint_corrupt_entry_falls_back_to_off(workspace_path: Path):
    data_dir = workspace_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / BrowserConfigStore.FILENAME).write_text(
        '{"page_load_timeout_ms": 45000, "fingerprint": {"enabled": true, "timezone": "白日梦"}}',
        encoding="utf-8",
    )
    store = BrowserConfigStore(data_dir)
    assert store.fingerprint() == {"enabled": False, "timezone": "", "language": ""}
    assert store.get()["page_load_timeout_ms"] == 45_000


def test_fingerprint_api_round_trip(workspace_path: Path):
    client = _client(workspace_path)

    assert client.get("/api/browser-config").get_json()["config"]["fingerprint"]["enabled"] is False

    saved = client.post(
        "/api/browser-config",
        json={"fingerprint": {"enabled": True, "timezone": "America/New_York", "language": "en-US"}},
    ).get_json()["config"]
    assert saved["fingerprint"] == {"enabled": True, "timezone": "America/New_York", "language": "en-US"}

    rejected = client.post(
        "/api/browser-config",
        json={"fingerprint": {"enabled": True, "timezone": "not a zone!", "language": "en-US"}},
    )
    assert rejected.status_code == 400
    assert client.get("/api/browser-config").get_json()["config"]["fingerprint"]["timezone"] == "America/New_York"


def test_unknown_timezone_is_rejected_when_the_machine_has_tz_data(workspace_path: Path):
    # Without system tz data (or the tzdata package) zoneinfo knows no zone at
    # all; refusing every timezone then would be worse than accepting a
    # well-formed name we cannot verify, so that case is deliberately lenient.
    if _known_timezones() is None:
        pytest.skip("本机没有 IANA 时区数据")
    store = BrowserConfigStore(workspace_path / "data")
    with pytest.raises(ValueError, match="未知时区"):
        store.save({"fingerprint": {"enabled": True, "timezone": "Mars/Olympus", "language": "en-US"}})
