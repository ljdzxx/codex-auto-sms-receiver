from __future__ import annotations

import logging
from pathlib import Path

import pytest

from src import upstream_bridge


LOGGER = logging.getLogger("gcash-test")
STALE_LINK = "https://checkoutshopper-live.adyen.com/checkoutshopper/previous-run"
FRESH_LINK = "https://checkoutshopper-live.adyen.com/checkoutshopper/fresh-run"


class FakeBridge:
    """Stand-in for the extension bridge; replays a scripted list of results."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    def request(self, kind: str, payload: dict, timeout: float | None = None):
        self.calls.append((kind, dict(payload)))
        if not self.responses:
            raise AssertionError(f"桥接调用超出脚本预期：{kind} {payload}")
        # The last scripted answer repeats so polling loops can settle on it.
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        return item(payload) if callable(item) else item


class FastClock:
    """Virtual clock so the real 3s poll interval does not slow the tests."""

    def __init__(self):
        self.now = 1_000.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += float(seconds)


def _probe(**overrides) -> dict:
    base = {
        "ok": True,
        "page_ready": True,
        "percent": 100,
        "progress_text": "",
        "progress_stage": "",
        "status_badge": "",
        "running": False,
        "result_visible": False,
        "result_value": "",
        "result_link": "",
        "result_session": "",
        "log_tail": [],
    }
    base.update(overrides)
    return base


def _finished_run(**overrides) -> dict:
    """The 「提炼结果」 panel shown with a fresh link — the success signal."""
    fields = {
        "percent": 100,
        "progress_stage": "任务完成",
        "progress_text": "GCash 跳转链接生成完成",
        "result_visible": True,
        "result_value": FRESH_LINK,
        "result_session": "oaics_new",
    }
    fields.update(overrides)
    return _probe(**fields)


def _failed_run(**overrides) -> dict:
    """100% with no result panel — the failure signal."""
    fields = {
        "percent": 100,
        "progress_stage": "任务异常",
        "progress_text": "任务失败",
        "log_tail": ["ERROR GCASH_METHOD_UNAVAILABLE: 当前 PH Checkout 尚未返回 GCash 支付方式"],
    }
    fields.update(overrides)
    return _probe(**fields)


@pytest.fixture
def fast_clock(monkeypatch):
    clock = FastClock()
    monkeypatch.setattr(upstream_bridge, "time", clock)
    return clock


def _install(monkeypatch, responses: list) -> FakeBridge:
    bridge = FakeBridge(responses)
    monkeypatch.setattr(upstream_bridge, "browser_bridge", bridge)
    return bridge


def test_bridge_tab_pins_requests_and_restores_the_previous_target(monkeypatch):
    bridge = _install(monkeypatch, [{"ok": True}])

    upstream_bridge._bridge_request("page_action", {"action": "outside"})
    with upstream_bridge._bridge_tab(77):
        upstream_bridge._bridge_request("page_action", {"action": "inside"})
        with upstream_bridge._bridge_tab(88):
            upstream_bridge._bridge_request("page_action", {"action": "nested"})
        upstream_bridge._bridge_request("page_action", {"action": "restored"})
    upstream_bridge._bridge_request("page_action", {"action": "after"})

    targets = [payload.get("tab_id") for _kind, payload in bridge.calls]
    assert targets == [None, 77, 88, 77, None]


def test_failed_run_is_not_rescued_by_the_previous_runs_link(monkeypatch, fast_clock):
    # The captured failure page still holds the PREVIOUS account's link inside a
    # hidden #resultValue. Only the panel's visibility may decide the outcome.
    baseline = _finished_run(result_value=STALE_LINK, result_session="oaics_old")
    _install(
        monkeypatch,
        [
            _probe(percent=12, running=True, progress_stage="提炼中"),
            _failed_run(result_value=STALE_LINK),
        ],
    )

    outcome = upstream_bridge._wait_for_gcash_outcome(LOGGER, baseline)

    assert outcome["success"] is False
    assert outcome["probe"]["progress_stage"] == "任务异常"


def test_successful_run_reports_the_fresh_link(monkeypatch, fast_clock):
    baseline = _failed_run()
    _install(
        monkeypatch,
        [
            _probe(percent=5, running=True, progress_stage="提炼中"),
            _finished_run(),
        ],
    )

    outcome = upstream_bridge._wait_for_gcash_outcome(LOGGER, baseline)

    assert outcome["success"] is True
    assert outcome["probe"]["result_value"] == FRESH_LINK


def test_start_is_detected_from_a_reset_even_without_a_running_flag(monkeypatch, fast_clock):
    # Some runs finish between two polls, so "#cancelButton visible" may never be
    # observed; the panel being reset from the baseline is enough to say it ran.
    baseline = _finished_run(result_value=STALE_LINK, result_session="oaics_old")
    _install(monkeypatch, [_finished_run()])

    outcome = upstream_bridge._wait_for_gcash_outcome(LOGGER, baseline)

    assert outcome["success"] is True


def test_unchanged_page_after_submit_raises_a_non_retryable_failure(monkeypatch, fast_clock):
    baseline = _failed_run()
    _install(monkeypatch, [_failed_run()])

    with pytest.raises(RuntimeError) as excinfo:
        upstream_bridge._wait_for_gcash_outcome(LOGGER, baseline)

    assert upstream_bridge._GCASH_FAILED_TOKEN in str(excinfo.value)
    assert "状态一直没有变化" in str(excinfo.value)


def test_scan_wait_requires_leaving_chatgpt_before_accepting_the_return(monkeypatch, fast_clock):
    _install(
        monkeypatch,
        [
            {"ok": True, "url": "https://chatgpt.com/"},
            {"ok": True, "url": "https://checkoutshopper-live.adyen.com/checkoutshopper/x"},
            {"ok": True, "url": "https://m.gcash.com/pay/abc"},
            {"ok": True, "url": "https://chatgpt.com/checkout/verify?x=1"},
        ],
    )

    scanned, url, stopped = upstream_bridge._wait_for_gcash_scan(LOGGER)

    assert scanned is True
    assert stopped is False
    assert url == "https://chatgpt.com/checkout/verify?x=1"


def test_scan_wait_exits_promptly_when_cancelled(monkeypatch, fast_clock):
    # No timeout any more: the scan waits forever unless the operator stops the
    # pipeline. A set cancel_event must break the wait and report stopped=True so
    # the running worker thread does not spin forever.
    import threading

    _install(monkeypatch, [{"ok": True, "url": "https://chatgpt.com/"}])
    cancel = threading.Event()
    cancel.set()

    scanned, url, stopped = upstream_bridge._wait_for_gcash_scan(LOGGER, cancel_event=cancel)

    assert scanned is False
    assert stopped is True


def test_scan_wait_exits_when_the_bound_tab_is_gone(monkeypatch, fast_clock):
    _install(monkeypatch, [{"ok": False, "error": "绑定的标签页 5 已不存在，请在调试页重新绑定"}])

    scanned, url, stopped = upstream_bridge._wait_for_gcash_scan(LOGGER)

    assert scanned is False
    assert stopped is False


def test_gcash_run_requires_two_distinct_bound_tabs(tmp_path: Path):
    settings = upstream_bridge.Settings(
        project_root=Path(__file__).resolve().parents[1],
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        browser_executable=None,
        browser_timeout_seconds=120,
        host="127.0.0.1",
        port=5015,
    )

    with pytest.raises(RuntimeError, match="未绑定标签页"):
        upstream_bridge._run_gcash_extraction(
            settings, {"email": "a@example.com"}, otp_provider=None
        )
    with pytest.raises(RuntimeError, match="不能绑定成同一个"):
        upstream_bridge._run_gcash_extraction(
            settings,
            {"email": "a@example.com", "gcash_login_tab_id": 3, "gcash_extract_tab_id": 3},
            otp_provider=None,
        )


def test_access_token_is_read_from_the_login_session_payload(monkeypatch):
    _install(monkeypatch, [{"ok": True}])

    assert upstream_bridge._read_gcash_access_token(LOGGER, {"accessToken": "tok-1"}) == "tok-1"
    assert upstream_bridge._read_gcash_access_token(LOGGER, {"access_token": "tok-2"}) == "tok-2"


def test_access_token_falls_back_to_reading_the_session_endpoint(monkeypatch):
    _install(
        monkeypatch,
        [{"ok": True, "status": 200, "body": '{"user":{"id":"u"},"accessToken":"tok-fetch"}'}],
    )

    assert upstream_bridge._read_gcash_access_token(LOGGER, {"user": {"id": "u"}}) == "tok-fetch"
