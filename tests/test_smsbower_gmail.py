import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.mailbox_store import MailboxStore
from src.smsbower_mail import (
    MAIL_STATUS_CANCEL,
    SmsbowerMailActivationGoneError,
    SmsbowerMailClient,
    SmsbowerMailCodePendingError,
    SmsbowerMailError,
    SmsbowerMailOutOfStockError,
)
from src.smsbower_mail_store import SmsbowerMailConfigStore, mask_api_key
from src.settings import Settings
from src.webapp import create_app


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


def make_client(responses, *, api_key="secret-key-value"):
    """Client whose transport replays ``responses`` and records the queries."""

    calls = []
    queue = list(responses)

    def http_get(url, params=None, headers=None, timeout=None):
        calls.append({"url": url, "params": dict(params or {})})
        return queue.pop(0)

    client = SmsbowerMailClient(api_key, http_get=http_get)
    return client, calls


# ------------------------------------------------------------ generated password


def test_generated_register_password_is_export_safe_and_mixed():
    from src.upstream_bridge import _generate_register_password

    for _ in range(200):
        password = _generate_register_password()
        assert len(password) == 12
        # Exported as the middle column of email----密码----密钥; a separator here
        # would split the line and corrupt every downstream reader.
        assert "----" not in password and "|" not in password
        assert password.isalnum() and password.isascii()
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)


# ------------------------------------------------------- registration progress


def test_update_registration_keeps_password_through_a_later_failure(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])

    store.update_registration("a@gmail.com", status="pending", password="Abc123def456")
    store.update_registration("a@gmail.com", status="failed", message="验证码两轮都未通过")

    secret = store.get_secret(email="a@gmail.com")
    # The account may already exist upstream; losing its password strands it.
    assert secret["password"] == "Abc123def456"
    row = store.list_accounts()[0]
    assert row["register_status"] == "failed"
    assert row["source"] == "smsbower_gmail"


def test_update_registration_ignores_an_unknown_address(tmp_path):
    store = MailboxStore(tmp_path)

    assert store.update_registration("nobody@gmail.com", status="failed") is False


# ------------------------------------------------------------------ 注册入口


def test_signup_enters_from_chatgpt_home_and_never_from_the_login_page():
    from src import upstream_bridge

    # 2026-08-12 直连实测：裸 GET /create-account 一律回 `Your session has ended`
    # （连续 5 轮，预热种会话无效），能进注册表单的只有 chatgpt.com 首页那条路。
    assert upstream_bridge._SIGNUP_ENTRY_URLS[0] == "https://chatgpt.com/"
    assert upstream_bridge._CHATGPT_HOME_RE.match(upstream_bridge._SIGNUP_ENTRY_URLS[0])
    # /create-account 只留作后备（会话真建起来时它是直达的），但绝不能再排第一。
    assert "https://auth.openai.com/create-account" in upstream_bridge._SIGNUP_ENTRY_URLS
    # /log-in 是登录页：往里填一个全新地址，OpenAI 回的是「Enter your password」
    # （/log-in/password），流程必死，而且极易被误读成"这个号已经注册过了"。
    for url in upstream_bridge._SIGNUP_ENTRY_URLS:
        assert "/log-in" not in url, f"注册入口不能是登录页：{url}"
    # login_with?screen_hint=signup 会被重定向回同一张会话中转页，白等一整轮。
    for url in upstream_bridge._SIGNUP_ENTRY_URLS:
        assert "login_with" not in url, f"注册入口不能是重定向端点：{url}"


def test_signup_flow_passes_the_signup_entry_ladder(monkeypatch, tmp_path):
    from src import upstream_bridge

    captured = {}

    def fake_open(settings, mailbox, *, email, logger, label, entry_urls=None, signup=False):
        captured["entry_urls"] = entry_urls
        captured["signup"] = signup
        raise RuntimeError("stop here — only the entry ladder matters")

    monkeypatch.setattr(upstream_bridge, "_open_login_and_submit_email", fake_open)
    monkeypatch.setattr(
        upstream_bridge,
        "_smsbower_mail_runtime",
        lambda settings: (
            SimpleNamespace(release=lambda *a, **k: True, set_status=lambda *a, **k: True),
            {"code_timeout_seconds": 120, "code_interval_seconds": 5},
        ),
    )
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: SimpleNamespace(logger=logging.getLogger("test.signup")),
    )
    settings = SimpleNamespace(data_dir=tmp_path, project_root=tmp_path)
    with pytest.raises(RuntimeError):
        upstream_bridge._run_account_signup(
            settings, {"email": "a@gmail.com", "mail_id": 4}
        )

    assert captured["entry_urls"] == upstream_bridge._SIGNUP_ENTRY_URLS
    # 注册模式必须禁止跟随"会话已结束"页的「Log in」链接——跟过去就从注册流程
    # 掉进登录流程，「Continue with password」会去 /log-in/password。
    assert captured["signup"] is True


def test_proxied_signup_enters_from_chatgpt_home(monkeypatch, tmp_path):
    from src import upstream_bridge

    # 代理下 auth.openai.com/create-account 拿不到注册表单：实测连续 5 轮全是
    # "Your session has ended"，过去之后又直接落 /log-in/password（日志
    # codex-a87e3d33c1101746f29f9537-6782ed72-a1）。改从 chatgpt.com 首页点右上角
    # 「Log in」进「Log in or sign up」弹窗。代理下连后备都不给 create-account。
    assert upstream_bridge._signup_entry_urls({}) == upstream_bridge._SIGNUP_ENTRY_URLS
    assert upstream_bridge._signup_entry_urls({})[0] == "https://chatgpt.com/"
    assert upstream_bridge._signup_entry_urls({"proxy": {"url": "http://x:1"}}) == (
        "https://chatgpt.com/",
    )
    # 首页判据不能把 /auth/login_with 这类子路由也算进去（它们仍按原逻辑走）。
    assert upstream_bridge._CHATGPT_HOME_RE.match("https://chatgpt.com/")
    assert not upstream_bridge._CHATGPT_HOME_RE.match("https://chatgpt.com/auth/login_with")

    captured = {}

    def fake_open(settings, mailbox, *, email, logger, label, entry_urls=None, signup=False):
        captured["entry_urls"] = entry_urls
        raise RuntimeError("stop here — only the entry ladder matters")

    monkeypatch.setattr(upstream_bridge, "_open_login_and_submit_email", fake_open)
    monkeypatch.setattr(
        upstream_bridge,
        "_smsbower_mail_runtime",
        lambda settings: (
            SimpleNamespace(release=lambda *a, **k: True, set_status=lambda *a, **k: True),
            {"code_timeout_seconds": 120, "code_interval_seconds": 5},
        ),
    )
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: SimpleNamespace(logger=logging.getLogger("test.signup")),
    )
    settings = SimpleNamespace(data_dir=tmp_path, project_root=tmp_path)
    with pytest.raises(RuntimeError):
        upstream_bridge._run_account_signup(
            settings,
            {"email": "a@gmail.com", "mail_id": 4, "proxy": {"url": "http://x:1"}},
        )
    assert captured["entry_urls"] == upstream_bridge._PROXY_SIGNUP_ENTRY_URLS


def test_third_party_idp_matcher_only_fires_on_real_providers():
    from src.upstream_bridge import _THIRD_PARTY_IDP_RE

    for url in (
        "https://accounts.google.com/v3/signin/identifier?flowName=GlifWebSignIn",
        "https://accounts.google.com/",
        "https://login.microsoftonline.com/common/oauth2/authorize",
        "https://appleid.apple.com/auth/authorize",
    ):
        assert _THIRD_PARTY_IDP_RE.match(url), url
    # OpenAI 自己的页面绝不能被当成风控拦截。
    for url in (
        "https://auth.openai.com/create-account",
        "https://auth.openai.com/email-verification",
        "https://chatgpt.com/#pricing",
        "https://auth.openai.com/log-in/password",
    ):
        assert not _THIRD_PARTY_IDP_RE.match(url), url


# ----------------------------------------------------------------- MFA（步骤 7-9）


def test_secret_plus_password_converts_the_record_to_password_totp(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration("a@gmail.com", status="registered", password="Abc123def456", plus_trial=True)

    # 步骤 10：拿到 Base32 密钥后素材就齐了。
    store.update_registration("a@gmail.com", status="success", totp_secret="JBSWY3DPEHPK3PXP")

    row = store.list_accounts()[0]
    assert row["source"] == "password_totp"
    assert row["register_status"] == "success"
    # 现在它是一个完整可用的登录素材了。
    assert row["otp_ready"] is True
    # smsbower 出身的账号单独成组、按 Plus 资格分段，且不带行尾的 ----0/1。
    grouped = store.export_original([row["id"]])
    assert grouped == {
        "smsbower_gmail": [
            "----有试用资格----",
            "a@gmail.com----Abc123def456----JBSWY3DPEHPK3PXP",
        ]
    }


def test_manual_edit_completes_a_half_registered_account(tmp_path):
    # 自动开 2FA 失败之后，用户在浏览器里手动开好，把密钥抄回来——清单里的「编辑」
    # 按钮走这条：密码 + 密钥齐了就自动改写成 password_totp 素材，账号立刻可用。
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration(
        "a@gmail.com", status="registered", password="Abc123def456", message="已注册但未开启 2FA：弹窗没出来"
    )
    account_id = store.list_accounts()[0]["id"]
    assert store.list_accounts()[0]["editable"] is True
    assert store.list_accounts()[0]["has_totp_secret"] is False

    row = store.update_manual_credentials(
        account_id, totp_secret="jbsw y3dp ehpk 3pxp", plus_trial=True
    )

    assert row["source"] == "password_totp"
    assert row["otp_ready"] is True and row["has_totp_secret"] is True
    assert row["register_status"] == "success"
    # 密钥本身绝不出现在清单接口里。
    assert "JBSWY3DPEHPK3PXP" not in json.dumps(row)
    assert store.export_original([account_id]) == {
        "smsbower_gmail": ["----有试用资格----", "a@gmail.com----Abc123def456----JBSWY3DPEHPK3PXP"]
    }


def test_manual_edit_keeps_existing_values_and_rejects_a_bad_secret(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_text("password_totp", "b@gmail.com----OldPass123----JBSWY3DPEHPK3PXP")
    account_id = store.list_accounts()[0]["id"]

    # 留空 = 保持原值：编辑框里的密钥永远是空的（接口从不回传），不这么定就会
    # "一保存把密钥清掉"。
    store.update_manual_credentials(account_id, password="", totp_secret="")
    secret = store.get_secret(account_id=account_id)
    assert secret["password"] == "OldPass123" and secret["totp_secret"] == "JBSWY3DPEHPK3PXP"

    # 只改密码：密钥留着，素材同步改写。
    store.update_manual_credentials(account_id, password="NewPass456")
    secret = store.get_secret(account_id=account_id)
    assert secret["password"] == "NewPass456"
    assert secret["import_material"] == "b@gmail.com----NewPass456----JBSWY3DPEHPK3PXP"

    # 手抄错的密钥必须当场报错：写进去只会让账号看着"就绪"、每次都算错验证码。
    with pytest.raises(ValueError, match="Base32"):
        store.update_manual_credentials(account_id, totp_secret="not-a-secret!")
    assert store.get_secret(account_id=account_id)["totp_secret"] == "JBSWY3DPEHPK3PXP"


def test_manual_edit_only_applies_to_registered_or_totp_accounts(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_text("generic_api", "c@icloud.com----KEY123")
    account_id = store.list_accounts()[0]["id"]

    assert store.list_accounts()[0]["editable"] is False
    with pytest.raises(ValueError, match="支持编辑"):
        store.update_manual_credentials(account_id, password="x")
    with pytest.raises(ValueError, match="不存在"):
        store.update_manual_credentials("nope", password="x")


def test_edit_endpoint_updates_the_account(client_app):
    client_app.store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    client_app.store.update_registration("a@gmail.com", status="registered", password="Abc123def456")
    account_id = client_app.store.list_accounts()[0]["id"]

    response = client_app.client.post(
        f"/api/accounts/{account_id}/credentials",
        json={"password": "", "totp_secret": "JBSWY3DPEHPK3PXP", "plus_trial": False},
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["account"]["otp_ready"] is True
    assert payload["account"]["source"] == "password_totp"
    # 密钥不出口。
    assert "JBSWY3DPEHPK3PXP" not in response.get_data(as_text=True)
    # 密码没被空字符串清掉。
    assert client_app.store.get_secret(account_id=account_id)["password"] == "Abc123def456"

    response = client_app.client.post(
        f"/api/accounts/{account_id}/credentials", json={"codex_status": "failed"}
    )
    assert response.status_code == 200
    assert response.get_json()["account"]["codex_status"] == "failed"
    response = client_app.client.post(
        f"/api/accounts/{account_id}/credentials", json={"codex_status": "success"}
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["account"]["codex_status"] == "success"
    assert payload["account"]["codex_message"] == "已手动标记为成功"
    assert client_app.client.post(
        f"/api/accounts/{account_id}/credentials", json={"codex_status": "pending"}
    ).status_code == 400

    assert client_app.client.post(
        f"/api/accounts/{account_id}/credentials", json={"totp_secret": "oops"}
    ).status_code == 400
    assert client_app.client.post(
        "/api/accounts/missing/credentials", json={"password": "x"}
    ).status_code == 404


def test_mfa_failure_keeps_the_account_registered_instead_of_failed(tmp_path):
    # 账号建成 + 租用号已 setStatus=3 结清之后，开 2FA 失败绝不能把整单判失败，
    # 否则一个可用账号会显示成"注册失败"。
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration("a@gmail.com", status="registered", password="Abc123def456", plus_trial=False)

    store.update_registration(
        "a@gmail.com", status="registered", message="已注册但未开启 2FA：弹窗没出来；无 Plus 免费资格"
    )

    row = store.list_accounts()[0]
    assert row["register_status"] == "registered"
    assert row["source"] == "smsbower_gmail"  # 没有密钥就不改写成 password_totp
    assert row["otp_ready"] is False
    # 密码没丢，用户可以手动补 2FA。
    assert store.get_secret(email="a@gmail.com")["password"] == "Abc123def456"
    # 导出仍拿得到已有信息（末列是 Plus 资格 0）。
    assert store.export_original([row["id"]]) == {
        "smsbower_gmail": ["----无试用资格----", "a@gmail.com----Abc123def456"]
    }


def test_mfa_dismisses_the_welcome_dialog_before_touching_the_settings_page(monkeypatch):
    from src import upstream_bridge

    # 导航到 #settings/Security 是整页刷新，"You're all set" 那个原生 <dialog>
    # 会重新弹出来（load 之后才画出来），showModal() 把整页 inert 掉。不先等它出现
    # 并点掉，后面每一次点击都落空，最后还被报成"点击 Authenticator app 后既没弹出
    # MFA 弹窗也没进入验证"——真因被藏了整整一轮。
    order = []

    monkeypatch.setattr(
        upstream_bridge,
        "_bridge_navigate",
        lambda url, **kwargs: order.append(("navigate", url)),
    )

    def fake_page_action(action, **payload):
        order.append((action, payload.get("wait_ms")))
        return {"ok": True, "dismissed": True, "dismissed_count": 1, "still_blocked": False}

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", fake_page_action)

    def fake_step(action, **kwargs):
        order.append((action, None))
        raise RuntimeError("stop here — only the ordering matters")

    monkeypatch.setattr(upstream_bridge, "_submit_login_step", fake_step)
    # 自动流程走不通时会转人工等待（见下面那个测试），这里只关心调用顺序，
    # 把等待窗口压到最小免得测试真的睡 30 分钟。
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(upstream_bridge, "_MFA_MANUAL_WAIT_SECONDS", 5.0)

    with pytest.raises(RuntimeError):
        upstream_bridge._run_mfa_enrollment(
            logging.getLogger("test.mfa"), label="注册", password="Abc123def456"
        )

    assert order[0] == ("navigate", upstream_bridge._SECURITY_SETTINGS_URL)
    # 关弹层必须排在 open_mfa_enroll 之前，而且要带等待窗口（不等就查不到）。
    assert order[1][0] == "dismiss_blocking_dialog"
    assert order[1][1] and order[1][1] > 0
    assert order[2][0] == "open_mfa_enroll"


def test_mfa_open_failure_waits_for_a_human_instead_of_skipping_the_account(monkeypatch):
    from src import upstream_bridge

    # 实测 logs/codex-52b3d167068baf48cc943dff-5afab245-a1.log：`open_mfa_enroll`
    # 回了阶段 error，程序直接记成"已注册但未开启 2FA"就去跑下一个账号了。
    # 密钥 OpenAI 只显示这一次，跳过去 = 这个账号废掉。所以**任何**一步失败都要卡住
    # 等人工，等人在浏览器里把密钥点出来再自动接上。
    actions: list[str] = []

    monkeypatch.setattr(upstream_bridge, "_bridge_navigate", lambda url, **kwargs: None)
    monkeypatch.setattr(upstream_bridge, "_dismiss_blocking_dialog", lambda *a, **k: True)
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)

    def fake_step(action, **kwargs):
        actions.append(action)
        if action == "open_mfa_enroll":
            # 两轮都回 error（_MFA_ROUNDS 内部重试完仍然失败）。
            return {"ok": True, "next_stage": "error"}
        if action == "mfa_submit_code":
            return {"ok": True, "verified": True}
        raise AssertionError(f"unexpected step: {action}")

    def fake_page_action(action, **payload):
        actions.append(action)
        if action == "mfa_reveal_secret" and payload.get("read_only"):
            # 人在浏览器里把密钥点出来了 → 自动流程接上继续。
            return {"ok": True, "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
        return {"ok": False, "error": "x"}

    monkeypatch.setattr(upstream_bridge, "_submit_login_step", fake_step)
    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", fake_page_action)

    saved: list[str] = []
    secret = upstream_bridge._run_mfa_enrollment(
        logging.getLogger("test.mfa"),
        label="注册",
        password="Abc123def456",
        on_secret=saved.append,
    )

    assert secret == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    assert saved == [secret], "密钥必须一读到就落盘，不能押在提交验证码的成败上"
    # 阶段不对时先自己重试一轮，仍不行才转人工（read_only 轮询）。
    assert actions.count("open_mfa_enroll") == upstream_bridge._MFA_ROUNDS
    assert "mfa_reveal_secret" in actions, "必须转人工等待，不能直接放弃这个账号"


def test_mfa_manual_wait_timeout_is_not_retried_a_second_time(monkeypatch):
    from src import upstream_bridge

    # 人工也没来（等满 30 分钟）之后，再等第二个 30 分钟毫无意义：带令牌的超时
    # 必须原样抛出去，由调用方记成"已注册但未开 2FA"。
    monkeypatch.setattr(upstream_bridge, "_bridge_navigate", lambda url, **kwargs: None)
    monkeypatch.setattr(upstream_bridge, "_dismiss_blocking_dialog", lambda *a, **k: True)
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(upstream_bridge, "_MFA_MANUAL_WAIT_SECONDS", 10.0)
    monkeypatch.setattr(
        upstream_bridge,
        "_submit_login_step",
        lambda action, **kwargs: {"ok": True, "next_stage": "dialog"},
    )
    waits: list[bool] = []

    def fake_page_action(action, **payload):
        if action == "mfa_reveal_secret":
            waits.append(bool(payload.get("read_only")))
        return {"ok": False, "error": "x"}

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", fake_page_action)

    with pytest.raises(RuntimeError, match=upstream_bridge._MFA_MANUAL_TIMEOUT_TOKEN):
        upstream_bridge._run_mfa_enrollment(
            logging.getLogger("test.mfa"), label="注册", password="Abc123def456"
        )
    # 只等了一轮人工（read_only 轮询），没有第二轮。
    assert waits.count(True) <= int(10.0 / upstream_bridge._MFA_MANUAL_POLL_SECONDS) + 1


def test_rental_settlement_is_always_logged(monkeypatch, caplog):
    from src import smsbower_mail, upstream_bridge

    # 失败收尾到底有没有调 setStatus 取消那个邮箱？日志必须说得一清二楚，
    # 不能靠"代码里有 release"想当然（号一直开着就一直计费）。
    class OkClient:
        def set_status(self, mail_id, status):
            return True

    class DeadClient:
        def set_status(self, mail_id, status):
            raise smsbower_mail.SmsbowerMailError("smsbower 邮箱接口：Bad key")

    class GoneClient:
        def set_status(self, mail_id, status):
            raise smsbower_mail.SmsbowerMailActivationGoneError("already canceled")

    logger = logging.getLogger("rental")
    with caplog.at_level(logging.INFO, logger="rental"):
        assert upstream_bridge._settle_rental(logger, OkClient(), 41, 2) is True
        assert upstream_bridge._settle_rental(logger, GoneClient(), 42, 2) is True
        assert upstream_bridge._settle_rental(logger, DeadClient(), 43, 3) is False

    text = caplog.text
    assert "mail_id=41" in text and "setStatus=2" in text and "取消并退回" in text
    assert "mail_id=42" in text and "已不存在" in text
    assert "mail_id=43" in text and "结算失败" in text and "仍在计费" in text


def test_rental_is_handed_back_when_the_browser_bridge_is_missing(monkeypatch, tmp_path):
    from src import upstream_bridge

    # 浏览器桥没连上 = 这个号一步都没用上，必须立刻退回，否则它会一直计费
    # 而日志里连一行记录都没有。
    released: list[tuple[int, int]] = []

    class Client:
        def set_status(self, mail_id, status):
            released.append((int(mail_id), int(status)))
            return True

    monkeypatch.setattr(
        upstream_bridge, "_smsbower_mail_runtime", lambda settings: (Client(), {})
    )
    monkeypatch.setattr(upstream_bridge, "_browser_flow_available", lambda: False)
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: SimpleNamespace(logger=logging.getLogger("test.bridge")),
    )

    with pytest.raises(RuntimeError, match="浏览器桥"):
        upstream_bridge.run_codex_only(
            SimpleNamespace(data_dir=tmp_path, project_root=tmp_path, log_dir=tmp_path),
            {"email": "a@gmail.com", "mail_id": 7, "register_account": True, "source": "smsbower_gmail"},
        )

    from src.smsbower_mail import MAIL_STATUS_CANCEL

    assert released == [(7, MAIL_STATUS_CANCEL)]


def test_a_missed_trusted_click_is_retried_not_fatal(monkeypatch):
    from src import upstream_bridge

    # 实测同一个账号连跑两遍：第一遍在"设置账号密码"报「可信点击落空：目标点被其它
    # 元素遮挡」整单作废，隔 3 分钟原样重跑一次就过（logs/codex-2ffe475cee4fb8bb73aa7c70
    # -1d27c48f vs -cbd917a5）。遮挡是瞬时的（新页面还在做视图过渡），而那一下点击
    # 根本没派发出去，所以整步重跑既安全又该做——不该由用户手动重跑。
    calls: list[str] = []
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)

    def flaky(action, **payload):
        calls.append(action)
        if len(calls) < 3:
            raise RuntimeError(
                "可信点击落空：目标点被其它元素遮挡（可能有未关闭的弹层）"
                " @ https://auth.openai.com/create-account/password"
            )
        return {"ok": True, "next_stage": "otp"}

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", flaky)
    result = upstream_bridge._submit_signup_password(
        logging.getLogger("test.click"), label="注册", password="Abc123def456"
    )
    assert result["next_stage"] == "otp"
    assert len(calls) == 3, "落空必须重试，而不是当场判死"

    # 其它错误照旧立刻抛出去，别把真失败拖成三倍时长。
    other: list[str] = []

    def hard(action, **payload):
        other.append(action)
        raise RuntimeError("设置密码失败：Incorrect email address or password")

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", hard)
    with pytest.raises(RuntimeError, match="Incorrect"):
        upstream_bridge._submit_signup_password(
            logging.getLogger("test.click"), label="注册", password="Abc123def456"
        )
    assert len(other) == 1


def test_tab_stage_settles_before_the_next_injection(monkeypatch):
    from src import upstream_bridge

    # URL 变了不等于页面能点了：新页面此时可能还在做视图过渡（旧视图淡出层压在
    # 新视图上）。落点判出来之后必须静置一小会儿，否则下一步的点击就落空。
    slept: list[float] = []
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda seconds: slept.append(seconds))
    monkeypatch.setattr(
        upstream_bridge,
        "_bridge_request",
        lambda kind, payload, **kwargs: {"url": "https://auth.openai.com/create-account/password"},
    )

    stage = upstream_bridge._wait_for_password_page(logging.getLogger("test.stage"), label="注册")

    assert stage == "create-account-password"
    assert slept == [upstream_bridge._PAGE_TRANSITION_SETTLE_SECONDS]


def test_continue_with_password_frame_teardown_is_not_a_failure(monkeypatch):
    from src import upstream_bridge

    # 点「Continue with password」本来就会导航到 /create-account/password，导航会
    # 销毁注入帧 —— `Frame with ID 0 was removed.` 是**点成功了**的表现。旧代码把它
    # 当致命错误抛出去，直接作废一个已经发出验证码的账号（还白烧一个取号）。
    # 实测 logs/codex-d230681a1023b30343738ede-35828900-a1.log。
    class Bridge:
        def __init__(self, url):
            self.url = url
            self.calls: list[str] = []

        def request(self, kind, payload, timeout=None):
            self.calls.append(kind)
            if kind == "page_action":
                raise RuntimeError("Frame with ID 0 was removed.")
            return {"ok": True, "url": self.url}

    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    # 两个落点必须分得开：/log-in/password 是登录页，把生成的密码填进去就是踩坑 #17。
    for url, expected in (
        ("https://auth.openai.com/create-account/password", "create-account-password"),
        ("https://auth.openai.com/log-in/password", "login-password"),
    ):
        fake = Bridge(url)
        monkeypatch.setattr(upstream_bridge, "browser_bridge", fake)
        stage = upstream_bridge._switch_to_password_signup(
            logging.getLogger("switch-password"), label="注册"
        )
        assert stage == expected, url
        assert "tab_url" in fake.calls


def test_password_page_probe_ignores_a_page_that_has_not_moved_yet(monkeypatch):
    from src import upstream_bridge

    # 页面还停在 /email-verification 时不能算落点，得继续等（否则"还没跳"会被当成
    # 已经到了密码页）。
    class Bridge:
        def request(self, kind, payload, timeout=None):
            return {"ok": True, "url": "https://auth.openai.com/email-verification"}

    monkeypatch.setattr(upstream_bridge, "browser_bridge", Bridge())
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    assert (
        upstream_bridge._wait_for_password_page(
            logging.getLogger("probe"), "注册", timeout=3.0
        )
        == ""
    )


def test_signup_password_null_result_is_frame_teardown_not_a_failure(monkeypatch):
    from src import upstream_bridge

    # 提交注册密码成功**本来就会**跳到 /email-verification 并销毁注入帧，而帧销毁
    # 有两种表现（踩坑 #1）：抛 `Frame with ID X was removed`，**或 executeScript
    # 静默返回 null → "页面动作返回空结果"**。第二种以前没人接，于是密码已经设好、
    # 页面已经在验证码页上，任务却在这里判死，连 120s 的取码都没等到
    # （logs/codex-d230681a1023b30343738ede-1e3b489f-a1.log）。
    class Bridge:
        def __init__(self, error, url):
            self.error = error
            self.url = url

        def request(self, kind, payload, timeout=None):
            if kind == "page_action":
                raise RuntimeError(self.error)
            return {"ok": True, "url": self.url}

    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    for error in ("页面动作返回空结果", "Frame with ID 0 was removed."):
        monkeypatch.setattr(
            upstream_bridge,
            "browser_bridge",
            Bridge(error, "https://auth.openai.com/email-verification"),
        )
        result = upstream_bridge._submit_signup_password(
            logging.getLogger("signup-password"), label="注册", password="Abc123def456"
        )
        assert result["next_stage"] == "otp", error
        assert result["frame_teardown"] is True

    # 页面还停在设密码页 = 还没跳，不能当落点；探不到就照实报错。
    monkeypatch.setattr(
        upstream_bridge,
        "browser_bridge",
        Bridge("页面动作返回空结果", "https://auth.openai.com/create-account/password"),
    )
    with pytest.raises(RuntimeError, match="没有落到验证码页"):
        upstream_bridge._submit_signup_password(
            logging.getLogger("signup-password"), label="注册", password="Abc123def456"
        )


def test_signup_link_click_survives_frame_teardown(monkeypatch):
    from src import upstream_bridge

    class Bridge:
        def __init__(self, url):
            self.url = url

        def request(self, kind, payload, timeout=None):
            if kind == "page_action":
                raise RuntimeError("Frame with ID 0 was removed.")
            return {"ok": True, "url": self.url}

    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    # /create-account/password 是 /create-account 的前缀，判据顺序不能反，
    # 否则设密码页会被认成邮箱表单再白提交一次邮箱。
    for url, expected in (
        ("https://auth.openai.com/create-account/password", "create-account-password"),
        ("https://auth.openai.com/create-account", "create-account"),
        ("https://auth.openai.com/email-verification", "otp"),
    ):
        monkeypatch.setattr(upstream_bridge, "browser_bridge", Bridge(url))
        result = upstream_bridge._click_signup_link(
            logging.getLogger("signup-link"), label="注册"
        )
        assert result["next_stage"] == expected, url


def test_retry_reuses_the_password_already_set_on_the_account(monkeypatch, tmp_path):
    from src import upstream_bridge

    # 重跑的账号：上一轮已经建号并设过密码（`update_registration` 在提交密码之前就
    # 落盘，正是为这一刻）。OpenAI 记得那个密码，本轮必须**沿用**它——另生成一个新
    # 密码就再也登不进这个已存在的账号了，而落到 /log-in/password 也不该判死刑。
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration("a@gmail.com", status="pending", password="OldPass123456")

    captured = {}

    def fake_resume(logger, *, label, email, password):
        captured["password"] = password
        return "otp"

    monkeypatch.setattr(
        upstream_bridge, "_open_login_and_submit_email", lambda *a, **k: "login-password"
    )
    monkeypatch.setattr(upstream_bridge, "_resume_with_known_password", fake_resume)
    # 用已存密码登进去之后不该再走"设置密码"，直接等验证码。
    monkeypatch.setattr(
        upstream_bridge,
        "_submit_signup_password",
        lambda *a, **k: pytest.fail("已有密码的账号不该再设一次密码"),
    )
    monkeypatch.setattr(
        upstream_bridge,
        "_wait_for_smsbower_code",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop at the code poll")),
    )
    monkeypatch.setattr(
        upstream_bridge,
        "_smsbower_mail_runtime",
        lambda settings: (
            SimpleNamespace(release=lambda *a, **k: True, set_status=lambda *a, **k: True),
            {"code_timeout_seconds": 120, "code_interval_seconds": 5},
        ),
    )
    monkeypatch.setattr(
        upstream_bridge,
        "_ensure_upstream_imports",
        lambda settings: SimpleNamespace(logger=logging.getLogger("resume-password")),
    )
    settings = SimpleNamespace(data_dir=tmp_path, project_root=tmp_path)
    with pytest.raises(RuntimeError, match="stop at the code poll"):
        upstream_bridge._run_account_signup(settings, {"email": "a@gmail.com", "mail_id": 4})

    assert captured["password"] == "OldPass123456"


def test_known_password_login_reads_its_landing_from_the_tab_url(monkeypatch):
    from src import upstream_bridge

    class Bridge:
        def __init__(self, url, page_action=None):
            self.url = url
            self.page_action = page_action or {"ok": True}

        def request(self, kind, payload, timeout=None):
            if kind == "page_action":
                return dict(self.page_action)
            return {"ok": True, "url": self.url}

    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        upstream_bridge, "browser_bridge", Bridge("https://auth.openai.com/email-verification")
    )
    assert (
        upstream_bridge._resume_with_known_password(
            logging.getLogger("known-password"),
            label="注册",
            email="a@gmail.com",
            password="OldPass123456",
        )
        == "otp"
    )

    # 密码对不上 = 这个地址确实被别人注册了，这才是终局，要分类成"已注册帐号"。
    monkeypatch.setattr(
        upstream_bridge,
        "browser_bridge",
        Bridge(
            "https://auth.openai.com/log-in/password",
            {"ok": True, "error_text": "Incorrect email address or password."},
        ),
    )
    with pytest.raises(RuntimeError, match=upstream_bridge._ACCOUNT_EXISTS_TOKEN):
        upstream_bridge._resume_with_known_password(
            logging.getLogger("known-password"),
            label="注册",
            email="a@gmail.com",
            password="OldPass123456",
        )


def test_mfa_secret_retries_then_tries_the_qr_then_waits_for_a_human(monkeypatch):
    from src import upstream_bridge

    # 密钥 OpenAI 只显示这一次：读不到就等于账号废掉。所以这一步必须
    # 3 轮重试 → 解二维码 → 卡住等人工，**绝不允许跳过去跑下一个账号**。
    calls: list[tuple[str, bool]] = []

    def fake_page_action(action, **payload):
        calls.append((action, bool(payload.get("read_only"))))
        if action == "mfa_capture_qr":
            return {"ok": False, "error": "弹窗里没有二维码"}
        if action == "mfa_reveal_secret":
            reads = [item for item in calls if item[0] == "mfa_reveal_secret"]
            # 前 3 轮自动读取一律读不到；转人工之后第 2 次轮询才被人点出来。
            if payload.get("read_only") and len(reads) >= 5:
                return {"ok": True, "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
            return {"ok": True, "secret": "", "otpauth": ""}
        raise AssertionError(f"unexpected action: {action}")

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", fake_page_action)
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)

    secret = upstream_bridge._reveal_totp_secret(
        logging.getLogger("mfa-reveal"), label="注册"
    )
    assert secret == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    auto_reads = [item for item in calls if item[0] == "mfa_reveal_secret" and not item[1]]
    assert len(auto_reads) == upstream_bridge._MFA_REVEAL_ROUNDS, "自动读取必须重试 3 轮"
    assert ("mfa_capture_qr", False) in calls, "读不到就必须试二维码"
    assert any(item[0] == "mfa_reveal_secret" and item[1] for item in calls), "必须转人工等待"


def test_mfa_secret_never_returns_empty_it_raises_instead(monkeypatch):
    from src import upstream_bridge

    # 一路都拿不到时只能抛错（外层会记成"已注册但未开 2FA"并保留密码），
    # 绝不能悄悄返回空串——那会让后面把空密钥当成功写进素材。
    monkeypatch.setattr(
        upstream_bridge,
        "_bridge_page_action",
        lambda action, **payload: {"ok": False, "error": "x"},
    )
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(upstream_bridge, "_MFA_MANUAL_WAIT_SECONDS", 10.0)
    with pytest.raises(RuntimeError, match="等待人工提供 2FA 密钥超时"):
        upstream_bridge._reveal_totp_secret(logging.getLogger("mfa-reveal"), label="注册")


def test_otpauth_uri_yields_the_secret(monkeypatch):
    from src import upstream_bridge

    assert (
        upstream_bridge._secret_from_otpauth(
            "otpauth://totp/ChatGPT:a@gmail.com?secret=jbswy3dpehpk3pxpjbswy3dpehpk3pxp&issuer=OpenAI"
        )
        == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    )
    assert upstream_bridge._secret_from_otpauth("otpauth://totp/x?issuer=OpenAI") == ""
    assert upstream_bridge._secret_from_otpauth("") == ""
    # 页面直接给出密钥时也走同一套规范化（带空格分组是常态）。
    assert upstream_bridge._safe_totp_secret("JBSW Y3DP EHPK 3PXP") == "JBSWY3DPEHPK3PXP"
    assert upstream_bridge._safe_totp_secret("not a secret!") == ""

    # 二维码兜底：DOM 里直接能读到 otpauth 时不用截图解码。
    calls: list[str] = []

    def fake_page_action(action, **payload):
        calls.append(action)
        return {
            "ok": True,
            "secret": "",
            "otpauth": "otpauth://totp/ChatGPT:a@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=OpenAI",
        }

    monkeypatch.setattr(upstream_bridge, "_bridge_page_action", fake_page_action)
    monkeypatch.setattr(upstream_bridge.time, "sleep", lambda _seconds: None)
    assert (
        upstream_bridge._reveal_totp_secret(logging.getLogger("mfa-reveal"), label="注册")
        == "JBSWY3DPEHPK3PXP"
    )
    assert calls == ["mfa_reveal_secret"], "第一轮就该拿到，不该白跑二维码和人工"


def test_qr_image_is_decoded_into_the_secret_including_dark_mode():
    cv2 = pytest.importorskip("cv2", reason="没装 opencv 时二维码兜底本来就会降级成人工")
    import base64

    from src import upstream_bridge

    encoder = getattr(cv2, "QRCodeEncoder", None)
    if encoder is None:
        pytest.skip("这个 opencv 版本不带 QR 编码器，无法在测试里造二维码")

    matrix = cv2.QRCodeEncoder_create().encode(
        "otpauth://totp/ChatGPT:a@gmail.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=OpenAI"
    )
    matrix = cv2.resize(matrix, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    # 截图时留的白边就是解码要的 quiet zone。
    matrix = cv2.copyMakeBorder(matrix, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)

    def as_data_url(image):
        return "data:image/png;base64," + base64.b64encode(
            cv2.imencode(".png", image)[1].tobytes()
        ).decode()

    logger = logging.getLogger("qr")
    for image in (matrix, cv2.bitwise_not(matrix)):  # 深色模式下二维码是反相的
        assert (
            upstream_bridge._decode_totp_qr(as_data_url(image), logger=logger, label="test")
            == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        )
    # 不是图片 / 空值一律安静地返回空串，交给人工兜底。
    assert upstream_bridge._decode_totp_qr("", logger=logger, label="test") == ""
    assert upstream_bridge._decode_image_data_url("not-a-data-url") == b""


def test_totp_secret_is_normalised_and_rejects_garbage(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration("a@gmail.com", status="registered", password="Abc123def456")

    # 页面上读到的密钥可能带空格分组。
    store.update_registration("a@gmail.com", status="success", totp_secret="JBSW Y3DP EHPK 3PXP")
    assert store.get_secret(email="a@gmail.com")["totp_secret"] == "JBSWY3DPEHPK3PXP"

    with pytest.raises(ValueError):
        store.update_registration("a@gmail.com", status="success", totp_secret="not-base32!!")


# --------------------------------------------------------------- 运行时提示队列


def test_notice_store_replays_only_what_is_new():
    from src.notice_store import NoticeStore

    store = NoticeStore()
    store.push("旧提示")
    # 第一次连上（after=-1）只要游标，不补历史——否则一开面板就弹一串过期提示。
    first = store.since(-1)
    assert first["notices"] == [] and first["seq"] == 1

    store.push("取码第 1 次：验证码还没到")
    store.push("取码成功：123456", level="success")
    fresh = store.since(first["seq"])

    assert [item["message"] for item in fresh["notices"]] == [
        "取码第 1 次：验证码还没到",
        "取码成功：123456",
    ]
    assert fresh["notices"][-1]["level"] == "success"
    # 同一个游标再问一次，不该重复推送。
    assert store.since(fresh["seq"])["notices"] == []


def test_notice_store_drops_blank_messages_and_caps_history():
    from src.notice_store import NoticeStore

    store = NoticeStore(limit=3)
    store.push("   ")
    assert store.since(0)["notices"] == []
    for index in range(5):
        store.push(f"第 {index} 条")

    kept = [item["message"] for item in store.since(0)["notices"]]
    assert kept == ["第 2 条", "第 3 条", "第 4 条"]


def test_notices_endpoint_returns_new_items(client_app):
    from src.notice_store import notices

    start = client_app.client.get("/api/notices?after=-1").get_json()
    notices.push("取码第 1 次：验证码还没到", scope="smsbower")

    payload = client_app.client.get(f"/api/notices?after={start['seq']}").get_json()

    assert payload["ok"] is True
    assert [item["message"] for item in payload["notices"]] == ["取码第 1 次：验证码还没到"]


# ------------------------------------------------------- Plus 免费资格（0/1 列）


def test_smsbower_export_is_grouped_by_plus_trial_without_the_flag_column(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations(
        [{"email": "a@gmail.com", "mail_id": 4}, {"email": "b@gmail.com", "mail_id": 5}]
    )
    for email, plus in (("a@gmail.com", True), ("b@gmail.com", False)):
        store.update_registration(email, status="registered", password="Abc123def456", plus_trial=plus)
        store.update_registration(email, status="success", totp_secret="JBSWY3DPEHPK3PXP")
    rows = {row["email"]: row["id"] for row in store.list_accounts()}

    grouped = store.export_original([rows["a@gmail.com"], rows["b@gmail.com"]])

    # 资格由段落标题表达，素材行本身保持干净（没有行尾的 ----0/1）。
    assert grouped == {
        "smsbower_gmail": [
            "----有试用资格----",
            "a@gmail.com----Abc123def456----JBSWY3DPEHPK3PXP",
            "",
            "----无试用资格----",
            "b@gmail.com----Abc123def456----JBSWY3DPEHPK3PXP",
        ]
    }
    for line in grouped["smsbower_gmail"]:
        assert not line.endswith("----0") and not line.endswith("----1")


def test_unprobed_plus_trial_counts_as_no_trial(tmp_path):
    # plus_trial 为 None（从没探测过）也归"无试用资格"，需求只有两个分组。
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "b@gmail.com", "mail_id": 5}])
    store.update_registration("b@gmail.com", status="registered", password="Xyz789ghi012")
    account_id = store.list_accounts()[0]["id"]

    assert store.export_original([account_id]) == {
        "smsbower_gmail": ["----无试用资格----", "b@gmail.com----Xyz789ghi012"]
    }


def test_non_smsbower_accounts_keep_their_own_group(tmp_path):
    # 只有 smsbower 出身的账号走资格分段，其它素材类型的分组不受影响。
    store = MailboxStore(tmp_path)
    store.import_text("password_totp", "old@example.com----pass----JBSWY3DPEHPK3PXP")
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    store.update_registration("a@gmail.com", status="registered", password="Abc123def456", plus_trial=True)
    rows = {row["email"]: row["id"] for row in store.list_accounts()}

    grouped = store.export_original([rows["old@example.com"], rows["a@gmail.com"]])

    assert grouped["password_totp"] == ["old@example.com----pass----JBSWY3DPEHPK3PXP"]
    assert grouped["smsbower_gmail"] == ["----有试用资格----", "a@gmail.com----Abc123def456"]


def test_plus_trial_line_survives_a_reimport(tmp_path):
    # 追加的 0/1 列不能把素材弄成无效行：password_totp 解析器会忽略密钥之后的扩展列。
    store = MailboxStore(tmp_path)

    result = store.import_text(
        "password_totp", "a@gmail.com----Abc123def456----JBSWY3DPEHPK3PXP----1"
    )

    assert result["invalid"] == 0 and result["inserted"] == 1
    secret = store.get_secret(email="a@gmail.com")
    assert secret["password"] == "Abc123def456"
    assert secret["totp_secret"] == "JBSWY3DPEHPK3PXP"


# --------------------------------------------------------------------- client


def test_acquire_parses_the_malformed_json_from_the_vendor_docs():
    # The published example is not valid JSON: a missing comma after `1` and a
    # trailing one before the brace. A live response shaped like the docs must
    # still work.
    client, calls = make_client([FakeResponse('{"status":1"mail":"a@gmail.com","mailId":4,}')])

    activation = client.acquire(max_price="0.5")

    assert activation.email == "a@gmail.com"
    assert activation.mail_id == 4
    assert calls[0]["url"].endswith("/getActivation")
    assert calls[0]["params"] == {
        "api_key": "secret-key-value",
        "service": "dr",
        "domain": "gmail.com",
        "maxPrice": "0.5",
    }


def test_acquire_omits_blank_optional_parameters():
    client, calls = make_client([FakeResponse('{"status":1,"mail":"a@gmail.com","mailId":7}')])

    client.acquire()

    assert "maxPrice" not in calls[0]["params"]
    assert "ref" not in calls[0]["params"]
    assert "alias" not in calls[0]["params"]


def test_acquire_maps_out_of_stock_to_its_own_error():
    client, _ = make_client([FakeResponse('{"status": 0, "error": "No mails yet"}')])

    with pytest.raises(SmsbowerMailOutOfStockError):
        client.acquire()


def test_fetch_code_returns_the_digits_and_maps_pending():
    client, calls = make_client(
        [
            FakeResponse('{"status": 0, "error": "Code has not been received yet, please try again later"}'),
            FakeResponse('{"status":1"code":"123456",}'),
        ]
    )

    with pytest.raises(SmsbowerMailCodePendingError):
        client.fetch_code(4)
    assert client.fetch_code(4) == "123456"
    assert calls[0]["params"]["mailId"] == "4"


def test_unknown_activation_is_classified_as_gone():
    client, _ = make_client([FakeResponse('{"status": 0, "error": "No activation found with such id"}')])

    with pytest.raises(SmsbowerMailActivationGoneError):
        client.set_status(4, MAIL_STATUS_CANCEL)


def test_release_never_raises_and_reports_failure():
    client, calls = make_client(
        [
            FakeResponse('{"status":1,"message":"Success"}'),
            FakeResponse('{"status": 0, "error": "Bad actual activation status"}'),
        ]
    )

    assert client.release(4, MAIL_STATUS_CANCEL) is True
    assert client.release(4, MAIL_STATUS_CANCEL) is False
    assert calls[0]["params"] == {"api_key": "secret-key-value", "id": "4", "status": MAIL_STATUS_CANCEL}


def test_network_failure_never_echoes_the_api_key():
    def http_get(url, params=None, headers=None, timeout=None):
        raise RuntimeError(f"failed to reach {url}?api_key=secret-key-value")

    client = SmsbowerMailClient("secret-key-value", http_get=http_get)

    with pytest.raises(SmsbowerMailError) as excinfo:
        client.acquire()
    assert "secret-key-value" not in str(excinfo.value)


def test_missing_api_key_is_reported_before_any_request():
    client = SmsbowerMailClient("", http_get=lambda *a, **k: pytest.fail("must not be called"))

    with pytest.raises(SmsbowerMailError):
        client.acquire()


# ---------------------------------------------------------------- config store


def test_config_store_masks_the_key_and_keeps_it_on_blank_resubmit(tmp_path):
    store = SmsbowerMailConfigStore(tmp_path)

    public = store.save({"api_key": "abcdefghijklmnop", "max_price": "0.5", "code_timeout_seconds": 200})

    assert public["api_key_configured"] is True
    assert public["next_account_interval_seconds"] == 60
    assert "api_key" not in public
    assert public["api_key_masked"] == mask_api_key("abcdefghijklmnop")
    assert "abcdefghijklmnop" not in json.dumps(public)
    assert public["code_timeout_seconds"] == 200
    assert public["code_interval_seconds"] == 5

    store.save({"api_key": "", "max_price": "", "next_account_interval_seconds": 90})
    assert store.get()["api_key"] == "abcdefghijklmnop"
    assert store.get()["max_price"] == ""
    assert store.get()["next_account_interval_seconds"] == 90


def test_config_store_rejects_bad_values(tmp_path):
    store = SmsbowerMailConfigStore(tmp_path)

    with pytest.raises(ValueError):
        store.save({"api_key": ""})
    store.save({"api_key": "abcdefghijklmnop"})
    with pytest.raises(ValueError):
        store.save({"max_price": "free"})
    with pytest.raises(ValueError):
        store.save({"code_timeout_seconds": 5})
    with pytest.raises(ValueError):
        # An interval at or above the timeout can never poll twice.
        store.save({"code_timeout_seconds": 60, "code_interval_seconds": 60})


def test_config_store_survives_a_corrupt_file(tmp_path):
    store = SmsbowerMailConfigStore(tmp_path)
    store.path.write_text("not json", encoding="utf-8")

    assert store.get()["api_key"] == ""
    assert store.public()["code_timeout_seconds"] == 120


# --------------------------------------------------------------- mailbox store


def test_import_activations_records_the_mail_id_and_pending_state(tmp_path):
    store = MailboxStore(tmp_path)

    result = store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])

    assert result == {"parsed": 1, "inserted": 1, "updated": 0, "invalid": 0, "superseded": []}
    row = store.list_accounts()[0]
    assert row["source"] == "smsbower_gmail"
    assert row["register_status"] == "pending"
    assert row["mail_id"] == 4
    # Nothing to log in with yet, so the account must not look runnable.
    assert row["otp_ready"] is False


def test_import_activations_rejects_entries_without_a_mail_id(tmp_path):
    store = MailboxStore(tmp_path)

    with pytest.raises(ValueError):
        store.import_activations([{"email": "a@gmail.com"}])
    assert store.list_accounts() == []


def test_re_renting_an_address_clears_the_previous_secrets(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_text("password_totp", "a@gmail.com----pass----JBSWY3DPEHPK3PXP")

    result = store.import_activations([{"email": "a@gmail.com", "mail_id": 9}])

    assert result["updated"] == 1
    secret = store.get_secret(email="a@gmail.com")
    assert secret["mail_id"] == 9
    assert "password" not in secret and "totp_secret" not in secret
    assert store.list_accounts()[0]["otp_ready"] is False


def test_re_renting_an_address_reports_the_replaced_activation(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])

    result = store.import_activations([{"email": "a@gmail.com", "mail_id": 9}])

    # The old id is unreachable from any record now, so the caller has to cancel
    # it or the rental keeps billing.
    assert result["superseded"] == [4]
    assert store.get_secret(email="a@gmail.com")["mail_id"] == 9


def test_export_of_a_pending_rental_is_just_the_address(tmp_path):
    store = MailboxStore(tmp_path)
    store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    account_id = store.list_accounts()[0]["id"]

    grouped = store.export_original([account_id])

    # 还没探测过 Plus 资格的（plus_trial 为 None）归入"无试用资格"段。
    assert grouped == {"smsbower_gmail": ["----无试用资格----", "a@gmail.com"]}


# ---------------------------------------------------------------------- webapp


class FakeMailClient:
    def __init__(self, activations=(), error=None):
        self._queue = list(activations)
        self._error = error
        self.released = []

    def acquire(self, **kwargs):
        if self._queue:
            return self._queue.pop(0)
        raise self._error or SmsbowerMailOutOfStockError("smsbower 邮箱接口：No mails yet")

    def release(self, mail_id, status):
        self.released.append((mail_id, status))
        return True


@pytest.fixture()
def client_app(tmp_path):
    settings = Settings(
        project_root=tmp_path,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        browser_executable=None,
        browser_timeout_seconds=60,
        host="127.0.0.1",
        port=5015,
    )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    mailbox_store = MailboxStore(settings.data_dir)
    created: dict = {}

    def factory(api_key):
        created["api_key"] = api_key
        return created["client"]

    batch: dict = {}

    def start_batch(emails, **kwargs):
        batch.clear()
        batch.update({"emails": list(emails), **kwargs})
        return {"id": "pipeline-1", "status": "queued", "mode": kwargs.get("mode")}

    app = create_app(
        settings,
        mailbox_store=mailbox_store,
        codex_manager=SimpleNamespace(
            availability=lambda: {"available": True, "reason": ""},
            runtime_config=lambda: {},
            list_jobs=lambda: [],
            pipeline_overview=lambda pipeline_id=None: {},
            start_batch=start_batch,
        ),
        smsbower_mail_client_factory=factory,
    )
    app.config["TESTING"] = True
    return SimpleNamespace(
        client=app.test_client(), store=mailbox_store, created=created, settings=settings, batch=batch
    )


def test_import_endpoint_requires_a_saved_api_key(client_app):
    client_app.created["client"] = FakeMailClient()

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 1})

    assert response.status_code == 400
    assert "API Key" in response.get_json()["error"]


def test_import_endpoint_acquires_and_stores(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop", "max_price": "0.4"})
    client_app.created["client"] = FakeMailClient(
        [SimpleNamespace(email="a@gmail.com", mail_id=1), SimpleNamespace(email="b@gmail.com", mail_id=2)]
    )

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 2})

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["acquired"] == 2 and payload["inserted"] == 2
    assert client_app.created["api_key"] == "abcdefghijklmnop"
    assert {row["email"] for row in client_app.store.list_accounts()} == {"a@gmail.com", "b@gmail.com"}


def test_import_endpoint_keeps_the_partial_batch_and_warns(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    client_app.created["client"] = FakeMailClient([SimpleNamespace(email="a@gmail.com", mail_id=1)])

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 3})

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["acquired"] == 1
    assert "No mails yet" in payload["warning"]
    assert len(client_app.store.list_accounts()) == 1


def test_import_endpoint_reports_a_total_failure(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    client_app.created["client"] = FakeMailClient()

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 2})

    assert response.status_code == 400
    assert client_app.store.list_accounts() == []


def test_import_endpoint_hands_back_activations_it_cannot_store(client_app, monkeypatch):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    fake = FakeMailClient([SimpleNamespace(email="a@gmail.com", mail_id=1)])
    client_app.created["client"] = fake
    monkeypatch.setattr(
        MailboxStore, "import_activations", lambda self, items: (_ for _ in ()).throw(OSError("disk full"))
    )

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 1})

    assert response.status_code == 500
    # Rented mailboxes cost money — an unstorable one must be given back.
    assert fake.released == [(1, MAIL_STATUS_CANCEL)]


def test_import_endpoint_hands_back_a_replaced_activation(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    client_app.store.import_activations([{"email": "a@gmail.com", "mail_id": 4}])
    fake = FakeMailClient([SimpleNamespace(email="a@gmail.com", mail_id=9)])
    client_app.created["client"] = fake

    response = client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 1})

    assert response.status_code == 200
    assert fake.released == [(4, MAIL_STATUS_CANCEL)]


def test_import_endpoint_validates_the_count(client_app):
    client_app.created["client"] = FakeMailClient()

    assert client_app.client.post("/api/accounts/import-smsbower-gmail", json={"count": 0}).status_code == 400


def test_acquire_register_endpoint_starts_a_one_at_a_time_pipeline(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop", "max_price": "0.4"})
    fake = FakeMailClient([SimpleNamespace(email="a@gmail.com", mail_id=1), SimpleNamespace(email="b@gmail.com", mail_id=2)])
    client_app.created["client"] = fake

    response = client_app.client.post(
        "/api/accounts/acquire-register-smsbower-gmail", json={"count": 2, "confirmed": True}
    )

    payload = response.get_json()
    assert response.status_code == 202 and payload["count"] == 2
    # 按钮点下去时一个号都还没租：号由流水线在每个账号收尾后逐个取。
    assert client_app.store.list_accounts() == []
    assert client_app.batch["emails"] == [] and client_app.batch["mode"] == "register"
    assert client_app.batch["supply_count"] == 2
    assert client_app.batch["supply_retry_seconds"] == 10
    assert client_app.batch["next_account_interval_seconds"] == 60

    supplier = client_app.batch["supplier"]
    assert supplier() == "a@gmail.com"
    assert [row["email"] for row in client_app.store.list_accounts()] == ["a@gmail.com"]
    assert supplier() == "b@gmail.com"
    assert {row["email"] for row in client_app.store.list_accounts()} == {"a@gmail.com", "b@gmail.com"}
    assert client_app.created["api_key"] == "abcdefghijklmnop"


def test_acquire_register_supplier_hands_back_mailboxes_it_cannot_store(client_app, monkeypatch):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    fake = FakeMailClient([SimpleNamespace(email="a@gmail.com", mail_id=1)])
    client_app.created["client"] = fake
    client_app.client.post("/api/accounts/acquire-register-smsbower-gmail", json={"count": 1, "confirmed": True})
    monkeypatch.setattr(
        MailboxStore, "import_activations", lambda self, items: (_ for _ in ()).throw(OSError("disk full"))
    )

    with pytest.raises(Exception):
        client_app.batch["supplier"]()

    # 租下来的号会计费，存不下就必须退回。
    assert fake.released == [(1, MAIL_STATUS_CANCEL)]


def test_acquire_register_endpoint_validates_its_input(client_app):
    client_app.created["client"] = FakeMailClient()

    # 未确认：这一步会真实花钱。
    assert client_app.client.post(
        "/api/accounts/acquire-register-smsbower-gmail", json={"count": 1}
    ).status_code == 400
    # 没有 API Key 时直接拒绝，别先起一条注定取不到号的流水线。
    assert client_app.client.post(
        "/api/accounts/acquire-register-smsbower-gmail", json={"count": 1, "confirmed": True}
    ).status_code == 400
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})
    assert client_app.client.post(
        "/api/accounts/acquire-register-smsbower-gmail", json={"count": 0, "confirmed": True}
    ).status_code == 400
    response = client_app.client.post(
        "/api/accounts/acquire-register-smsbower-gmail", json={"count": 1000, "confirmed": True}
    )
    assert response.status_code == 202
    assert client_app.batch["supply_count"] == 1000


def test_config_endpoint_never_returns_the_raw_key(client_app):
    client_app.client.post("/api/smsbower-mail-config", json={"api_key": "abcdefghijklmnop"})

    body = client_app.client.get("/api/smsbower-mail-config").get_data(as_text=True)

    assert "abcdefghijklmnop" not in body
    assert json.loads(body)["config"]["api_key_configured"] is True
