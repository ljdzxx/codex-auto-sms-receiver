from __future__ import annotations

import pytest

from src import upstream_bridge


class RecordingBridge:
    """Captures every bridge call so ordering can be asserted."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.response = {"ok": True, "mode": "fixed_servers"}

    def request(self, kind: str, payload: dict, timeout: float | None = None):
        self.calls.append((kind, dict(payload)))
        return self.response


@pytest.fixture
def bridge(monkeypatch):
    fake = RecordingBridge()
    monkeypatch.setattr(upstream_bridge, "browser_bridge", fake)
    return fake


def test_apply_proxy_forwards_the_assigned_endpoint(bridge):
    proxy = {
        "id": "abc123",
        "scheme": "http",
        "host": "1.2.3.4",
        "port": 8001,
        "username": "u",
        "password": "p",
        "label": "http://***:***@1.2***.4:8001",
    }
    upstream_bridge._bridge_apply_proxy({"email": "a@b.c", "proxy": proxy})
    assert bridge.calls == [("proxy_apply", {"proxy": proxy})]


def test_apply_proxy_sends_null_so_the_browser_drops_a_stale_proxy(bridge):
    # An account with no assignment must actively clear the previous account's
    # proxy rather than silently inherit it.
    upstream_bridge._bridge_apply_proxy({"email": "a@b.c"})
    assert bridge.calls == [("proxy_apply", {"proxy": None})]


def test_apply_proxy_never_raises_when_the_browser_refuses(bridge, caplog):
    bridge.response = {"ok": False, "error": "当前浏览器不支持 chrome.proxy 接口"}
    upstream_bridge._bridge_apply_proxy({"email": "a@b.c"}, label="仅登录")
    # Losing the proxy is logged, but must not abort an otherwise healthy job.
    assert "设置浏览器代理返回失败" in caplog.text


def test_proxy_is_applied_before_the_browser_is_cleaned_and_navigates(bridge, monkeypatch):
    # _login_account_in_browser drives the real ordering; stub everything after
    # the cleanup so the test stays focused on "proxy first".
    import logging
    import types

    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: types.SimpleNamespace(logger=logging.getLogger("proxy-order-test")),
    )

    class Stop(RuntimeError):
        pass

    def stop_navigation(url, **kwargs):
        raise Stop(url)

    monkeypatch.setattr(upstream_bridge, "_bridge_navigate", stop_navigation)
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api", "proxy": {"scheme": "http", "host": "9.9.9.9", "port": 1}},
            otp_provider=lambda: "000000",
        )
    kinds = [kind for kind, _payload in bridge.calls]
    assert kinds[:2] == ["proxy_apply", "cleanup"]


def test_bridge_sends_the_configured_browser_budgets(bridge, monkeypatch):
    # The extension has no access to the backend config, so every navigate /
    # page_action payload carries the budget it must honour.
    monkeypatch.setattr(
        upstream_bridge,
        "_browser_config",
        lambda: {"page_load_timeout_ms": 90_000, "element_wait_timeout_ms": 60_000},
    )
    upstream_bridge._bridge_navigate("https://chatgpt.com/", retries=0)
    upstream_bridge._bridge_page_action("submit_email", email="a@b.c")
    kinds = dict((kind, payload) for kind, payload in bridge.calls)
    assert kinds["navigate"]["page_load_timeout_ms"] == 90_000
    assert kinds["page_action"]["element_wait_timeout_ms"] == 60_000


def test_backend_wait_is_derived_from_the_configured_budget(bridge, monkeypatch):
    monkeypatch.setattr(
        upstream_bridge,
        "_browser_config",
        lambda: {"page_load_timeout_ms": 120_000, "element_wait_timeout_ms": 100_000},
    )
    seen: list[float] = []

    def capture(kind, payload, timeout=None):
        seen.append(float(timeout))
        return {"ok": True}

    monkeypatch.setattr(bridge, "request", capture)
    upstream_bridge._bridge_navigate("https://chatgpt.com/", retries=0)
    upstream_bridge._bridge_page_action("submit_email", email="a@b.c")
    # Both must exceed the matching browser-side budget (orphan-job guard).
    assert seen[0] > 120.0
    assert seen[1] > 100.0 * 3


class ScriptedBridge:
    """Replays scripted answers per bridge kind and records the call order."""

    def __init__(self, page_action_results):
        self.page_action_results = list(page_action_results)
        self.calls: list[str] = []
        self.urls: list[str] = []
        self.payloads: dict[str, dict] = {}

    def request(self, kind: str, payload: dict, timeout: float | None = None):
        self.calls.append(kind)
        self.payloads.setdefault(kind, dict(payload))
        if kind == "navigate":
            self.urls.append(str(payload.get("url") or ""))
        if kind != "page_action":
            return {"ok": True, "url": "https://chatgpt.com/auth/login_with?callback_path=/"}
        item = self.page_action_results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _login_bridge(monkeypatch, page_action_results):
    import logging
    import types

    fake = ScriptedBridge(page_action_results)
    monkeypatch.setattr(upstream_bridge, "browser_bridge", fake)
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: types.SimpleNamespace(logger=logging.getLogger("login-shell-test")),
    )
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    return fake


def test_login_with_shell_reloads_once_then_succeeds(monkeypatch):
    # The page loaded but chatgpt.com served the logged-out SPA shell instead of
    # redirecting; only a fresh request can fix it, so one reload is tried before
    # the entry is abandoned.
    shell = {"ok": False, "error": "login_with_shell：登录页停在 chatgpt.com 未跳转到 auth.openai.com，需要重新加载"}
    fake = _login_bridge(monkeypatch, [shell, {"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert fake.calls == ["proxy_apply", "cleanup", "navigate", "page_action", "reload", "page_action"]


def test_dead_end_entry_falls_through_to_the_next_login_url(monkeypatch):
    # Hammering one URL cannot fix a page that loads but refuses to redirect —
    # after one reload the flow must try a DIFFERENT entry point.
    shell = {"ok": False, "error": "login_with_shell：未跳转"}
    fake = _login_bridge(monkeypatch, [shell, shell, {"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert fake.calls == [
        "proxy_apply", "cleanup",
        "navigate", "page_action", "reload", "page_action",   # 入口 1：auth.openai.com/log-in
        "navigate", "page_action",                            # 入口 2：chatgpt.com 落地页
    ]
    # The heavy chatgpt.com SPA login route must never be the first thing tried.
    assert fake.urls[0] == "https://auth.openai.com/log-in?usernameKind=email"
    assert fake.urls[1] == "https://chatgpt.com/"
    assert upstream_bridge._LOGIN_ENTRY_URLS[-1] == upstream_bridge._LOGIN_WITH_URL


def test_missing_email_box_after_the_step_already_passed_never_reloads(monkeypatch):
    import logging

    # 实测（logs/codex-d230681a1023b30343738ede-ed6497f6-a1）：点回中转页的登录控件
    # 后 OpenAI 直接把我们送回 /email-verification（Check your inbox +「Continue
    # with password」）。那页当然没有邮箱框，旧代码把「未找到邮箱输入框」当成"入口
    # 是死路"重新加载入口，等于把已经拿到的进度扔掉，还白烧一个取号。
    class Bridge:
        def __init__(self):
            self.calls: list[str] = []

        def request(self, kind, payload, timeout=None):
            self.calls.append(kind)
            if kind == "page_action":
                raise RuntimeError("[Codex] 未找到邮箱输入框 @ https://auth.openai.com/email-verification")
            if kind == "tab_url":
                return {"ok": True, "url": "https://auth.openai.com/email-verification"}
            return {"ok": True}

    fake = Bridge()
    monkeypatch.setattr(upstream_bridge, "browser_bridge", fake)
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)

    stage = upstream_bridge._open_login_and_submit_email(
        None,
        {"email": "a@b.c"},
        email="a@b.c",
        logger=logging.getLogger("already-past-email"),
        label="注册",
        entry_urls=("https://chatgpt.com/",),
    )
    # 已经在验证码页了：照实回 otp，让上层去点「Continue with password」。
    assert stage == "otp"
    assert "reload" not in fake.calls
    assert fake.calls.count("navigate") == 1
    assert fake.calls.count("page_action") == 1


def test_all_entries_exhausted_reports_the_ip_hint(monkeypatch):
    shell = {"ok": False, "error": "login_with_shell：未跳转"}
    fake = _login_bridge(monkeypatch, [dict(shell) for _ in range(6)])
    with pytest.raises(RuntimeError, match="个登录入口都没能进入邮箱表单") as caught:
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    # The operator needs to know where to look next.
    assert "代理" in str(caught.value)
    assert fake.urls == list(upstream_bridge._LOGIN_ENTRY_URLS)
    assert fake.calls.count("page_action") == 6
    assert fake.calls.count("reload") == 3


def test_unrelated_page_errors_are_not_retried_at_all(monkeypatch):
    # A genuine "wrong page" failure must fail fast instead of walking the ladder.
    fake = _login_bridge(monkeypatch, [{"ok": False, "error": "未识别页面阶段: unknown"}])
    with pytest.raises(RuntimeError, match="未识别页面阶段"):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert "reload" not in fake.calls
    assert fake.calls.count("page_action") == 1
    assert len(fake.urls) == 1


def test_navigate_asks_the_browser_to_stop_waiting_once_the_form_exists(monkeypatch):
    # Waiting for a full page load before typing the email was several seconds of
    # dead time per account; the browser is told which element is enough.
    fake = _login_bridge(monkeypatch, [{"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    selector = fake.payloads["navigate"].get("ready_selector") or ""
    assert 'input[type="email"]' in selector
    assert "/auth/login_with" in selector  # the 登录 link also counts as ready


def test_login_entry_does_not_sleep_between_navigate_and_typing(monkeypatch):
    # A blanket sleep after navigate is pure dead time now that navigate returns
    # when the form is on screen.
    slept: list[float] = []
    fake = _login_bridge(monkeypatch, [{"ok": True, "next_stage": "otp"}])
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda seconds: slept.append(float(seconds)))

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert slept == []
    assert fake.calls == ["proxy_apply", "cleanup", "navigate", "page_action"]


def test_unknown_stage_after_email_fails_fast_with_the_page_dumped(monkeypatch, caplog):
    # Nothing said "OTP sent". Polling the mailbox anyway burned 90s and then
    # blamed the mailbox ("HTTP 200 但未提取到验证码") for a mail never sent.
    import logging

    fake = _login_bridge(monkeypatch, [{
        "ok": True,
        "next_stage": "",
        "state": {
            "url": "https://auth.openai.com/log-in",
            "title": "OpenAI",
            "headings": ["请稍候"],
            "buttons": [{"text": "继续", "type": "submit"}],
            "body_preview": "正在验证你是否是真人",
        },
    }])
    polled: list[str] = []
    monkeypatch.setattr(
        upstream_bridge,
        "_wait_for_email_otp",
        lambda *a, **k: polled.append("polled") or "000000",
    )
    with caplog.at_level(logging.WARNING):
        with pytest.raises(RuntimeError, match="提交邮箱后落到未识别页面"):
            upstream_bridge._login_account_in_browser(
                None,
                {"email": "a@b.c", "source": "generic_api"},
                otp_provider=lambda: "000000",
            )
    assert polled == []  # never waited on the mailbox
    assert "auth.openai.com/log-in" in caplog.text
    assert "正在验证你是否是真人" in caplog.text
    assert fake.calls.count("page_action") == 1


def test_session_ended_page_is_clicked_again_instead_of_giving_up(monkeypatch):
    # auth.openai.com can bounce straight back to "你的会话已结束" after a click.
    # The 登录 control is still right there, so the step must be re-run (it starts
    # by clicking) rather than the entry written off.
    bounce = {"ok": False, "error": "login_retry_click：页面仍停在「你的会话已结束」，还有可点的登录控件，需要再点一次"}
    fake = _login_bridge(monkeypatch, [bounce, bounce, bounce, {"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    # One navigate, then click-click-click-succeed on the SAME entry: no reload,
    # no switching to another URL.
    assert fake.calls == ["proxy_apply", "cleanup", "navigate", "page_action", "page_action", "page_action", "page_action"]
    assert fake.urls == ["https://auth.openai.com/log-in?usernameKind=email"]


def test_frame_teardown_after_a_click_also_re_enters_the_flow(monkeypatch):
    # A click that navigates destroys the injected frame; that is progress, not
    # failure, so the step re-runs on the new page.
    teardown = RuntimeError("Frame with ID 0 was removed.")
    fake = _login_bridge(monkeypatch, [teardown, {"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert fake.calls == ["proxy_apply", "cleanup", "navigate", "page_action", "page_action"]


def test_endless_bounce_still_moves_on_to_the_next_entry(monkeypatch):
    # Clicking must not loop forever if the page never yields the form.
    bounce = {"ok": False, "error": "login_retry_click：还有可点的登录控件"}
    fake = _login_bridge(monkeypatch, [dict(bounce) for _ in range(30)])
    with pytest.raises(RuntimeError, match="个登录入口都没能进入邮箱表单"):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert fake.urls == list(upstream_bridge._LOGIN_ENTRY_URLS)
    # 6 click rounds per entry × 3 entries.
    assert fake.calls.count("page_action") == upstream_bridge._LOGIN_CLICK_ROUNDS * 3


def test_bounce_back_to_session_ended_after_submitting_email_clicks_again(monkeypatch):
    # The interstitial can reappear AFTER the email was submitted. Failing there
    # reported "落到未识别页面 / 你的会话已结束" and stopped, when the 登录 control
    # was sitting right there waiting to be clicked.
    bounce = {"ok": False, "error": "login_retry_click：提交邮箱后又回到「你的会话已结束」，需要重新点击登录进入流程"}
    fake = _login_bridge(monkeypatch, [bounce, {"ok": True, "next_stage": "otp"}])

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    # Same entry, clicked again — no reload, no entry switch, no fail-fast.
    assert fake.calls == ["proxy_apply", "cleanup", "navigate", "page_action", "page_action"]
    assert fake.urls == ["https://auth.openai.com/log-in?usernameKind=email"]


def test_proxied_login_does_not_block_on_a_page_that_never_finishes_loading(monkeypatch):
    # chatgpt.com holds connections open; behind a proxy the tab can sit in
    # 'loading' forever while its header is perfectly usable. Blocking on the
    # load event produced an endless "标签页加载超时" retry loop, so the navigate
    # must hand over to the element wait instead — while still pausing long
    # enough for Cloudflare's JS detection to finish scoring.
    slept: list[float] = []
    fake = _login_bridge(monkeypatch, [{"ok": True, "next_stage": "otp"}])
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda seconds: slept.append(float(seconds)))

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {
                "email": "a@b.c",
                "source": "generic_api",
                "proxy": {"scheme": "http", "host": "1.2.3.4", "port": 8001, "country_code": "JP"},
            },
            otp_provider=lambda: "000000",
        )
    assert fake.payloads["navigate"].get("ready_selector")
    assert slept == [upstream_bridge._PROXY_SETTLE_SECONDS]


def test_navigate_timeout_is_survivable_for_login_entries(monkeypatch):
    # The load event says nothing about whether the Log in button is clickable.
    calls: list[str] = []

    class TimingOutBridge:
        def request(self, kind, payload, timeout=None):
            calls.append(kind)
            if kind == "navigate":
                raise upstream_bridge.BrowserBridgeTimeout("浏览器桥接超时：navigate")
            return {"ok": True}

    monkeypatch.setattr(upstream_bridge, "browser_bridge", TimingOutBridge())
    result = upstream_bridge._bridge_navigate(
        "https://chatgpt.com/", retries=0, tolerate_timeout=True
    )
    assert result["load_timeout"] is True
    assert calls == ["navigate"]  # no pointless re-navigation

    # Without the flag a timeout is still a hard error.
    with pytest.raises(RuntimeError, match="超时"):
        upstream_bridge._bridge_navigate("https://chatgpt.com/", retries=0)


def test_direct_login_keeps_the_fast_path(monkeypatch):
    # Without a proxy nothing is being scored against us, so keep the speed-up.
    slept: list[float] = []
    fake = _login_bridge(monkeypatch, [{"ok": True, "next_stage": "otp"}])
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda seconds: slept.append(float(seconds)))

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(upstream_bridge, "_wait_for_email_otp", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "000000",
        )
    assert fake.payloads["navigate"].get("ready_selector")
    assert slept == []


def test_proxy_geo_reaches_the_browser_for_locale_alignment(monkeypatch):
    from src.proxy_store import ProxyStore

    record = {
        "id": "abc", "scheme": "http", "host": "1.2.3.4", "port": 8001,
        "username": "", "password": "", "url_masked": "http://1.2***.4:8001",
        "country_code": "JP", "timezone": "Asia/Tokyo",
    }
    config = ProxyStore.browser_config(record)
    # Without these the browser announces zh-CN on a Japanese exit IP.
    assert config["country_code"] == "JP"
    assert config["timezone"] == "Asia/Tokyo"


def _stage_bridge(monkeypatch, page_action_result, tab_urls):
    """Bridge whose tab_url answers walk through `tab_urls` as it is polled."""
    import logging
    import types

    urls = list(tab_urls)

    class Bridge:
        def __init__(self):
            self.calls: list[str] = []

        def request(self, kind, payload, timeout=None):
            self.calls.append(kind)
            if kind == "page_action":
                return page_action_result
            if kind == "tab_url":
                return {"ok": True, "url": urls.pop(0) if len(urls) > 1 else urls[0]}
            return {"ok": True}

    fake = Bridge()
    monkeypatch.setattr(upstream_bridge, "browser_bridge", fake)
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: types.SimpleNamespace(logger=logging.getLogger("stage-test")),
    )
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _s: None)
    return fake


def test_late_email_verification_navigation_is_not_treated_as_failure(monkeypatch):
    # A localized UI ("お帰りなさい") defeats the in-page text judgement, and a slow
    # proxy lands /email-verification after its window closed. The OTP WAS sent,
    # so the run must continue instead of being killed.
    unknown = {
        "ok": True,
        "next_stage": "",
        "state": {"url": "https://auth.openai.com/log-in", "title": "お帰りなさい - OpenAI"},
    }
    _stage_bridge(
        monkeypatch,
        unknown,
        ["https://auth.openai.com/log-in", "https://auth.openai.com/email-verification"],
    )
    reached: list[str] = []
    monkeypatch.setattr(
        upstream_bridge,
        "_wait_for_email_otp",
        lambda *a, **k: reached.append("otp") or "123456",
    )

    class Stop(RuntimeError):
        pass

    monkeypatch.setattr(
        upstream_bridge,
        "_submit_login_step",
        lambda *a, **k: (_ for _ in ()).throw(Stop()),
    )
    with pytest.raises(Stop):
        upstream_bridge._login_account_in_browser(
            None,
            {"email": "a@b.c", "source": "generic_api"},
            otp_provider=lambda: "123456",
        )
    assert reached == ["otp"]  # went on to collect the code that was really sent


def test_page_that_never_moves_still_fails_with_the_dump(monkeypatch, caplog):
    import logging

    unknown = {
        "ok": True,
        "next_stage": "",
        "state": {"url": "https://auth.openai.com/log-in", "title": "お帰りなさい - OpenAI"},
    }
    _stage_bridge(monkeypatch, unknown, ["https://auth.openai.com/log-in"])
    monkeypatch.setattr(upstream_bridge, "_wait_for_post_email_landing", lambda *a, **k: "")
    with caplog.at_level(logging.WARNING):
        with pytest.raises(RuntimeError, match="提交邮箱后落到未识别页面"):
            upstream_bridge._login_account_in_browser(
                None,
                {"email": "a@b.c", "source": "generic_api"},
                otp_provider=lambda: "000000",
            )
    assert "お帰りなさい" in caplog.text


def test_login_entry_pins_email_login():
    # The page otherwise sometimes defaults to the phone-number form, which has
    # no email box at all — the step would then wait out its whole budget.
    assert upstream_bridge._LOGIN_ENTRY_URLS[0] == "https://auth.openai.com/log-in?usernameKind=email"
    assert "usernameKind=email" in upstream_bridge._OPENAI_LOGIN_URL


def test_proxied_run_only_uses_chatgpt_com_as_the_entry(monkeypatch):
    # Through a proxy the auth.openai.com entries just bounce back to
    # "你的会话已结束"; everything funnels through chatgpt.com anyway, so trying
    # the others first only burns an attempt each.
    bounce = {"ok": False, "error": "login_retry_click：还有可点的登录控件"}
    fake = _login_bridge(monkeypatch, [dict(bounce) for _ in range(30)])
    with pytest.raises(RuntimeError, match="个登录入口都没能进入邮箱表单"):
        upstream_bridge._login_account_in_browser(
            None,
            {
                "email": "a@b.c",
                "source": "generic_api",
                "proxy": {"scheme": "http", "host": "1.2.3.4", "port": 8001, "country_code": "JP"},
            },
            otp_provider=lambda: "000000",
        )
    assert fake.urls == ["https://chatgpt.com/"]
    assert upstream_bridge._PROXY_LOGIN_ENTRY_URLS == ("https://chatgpt.com/",)
