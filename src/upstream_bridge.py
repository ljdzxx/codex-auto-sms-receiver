from __future__ import annotations

import json
import logging
import os
import re
import secrets
import string
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from dotenv import dotenv_values

from .browser_bridge import BrowserBridgeTimeout, browser_bridge
from .hero_sms import install_hero_sms_patch
from .mailbox_store import MailboxStore
from .settings import Settings
from .totp_auth import current_totp
from .upstream_location import resolve_upstream_root


SAFE_DEFAULTS = {
    "OUTLOOK_FETCH_MODE": "direct",
    "CODEX_OAUTH_DRIVER": "protocol",
    "CODEX_AUTH_URL_SOURCE": "local",
    "PROXY_POOL": "",
    "USE_EMAIL_SERVICE": "True",
}

GENERIC_API_OTP_MAX_WAIT_SECONDS = 90
GENERIC_API_OTP_POLL_INTERVAL_SECONDS = 3


def _channel_code_wait(channel: str, default: int) -> int:
    """Resolve the per-channel SMS-code wait, falling back to the global default.

    The UI persists HERO_SMS_CODE_WAIT / SMSBOWER_CODE_WAIT alongside the global
    SMS_CODE_WAIT. Each channel gets its own timeout; when a channel override is
    unset or unparsable we fall back to the global wait passed in as ``default``.
    """

    key = {"hero": "HERO_SMS_CODE_WAIT", "smsbower": "SMSBOWER_CODE_WAIT"}.get(
        str(channel or "").strip().lower()
    )
    if not key:
        return default
    try:
        value = int(str(os.getenv(key, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _generate_signup_password(length: int = 16) -> str:
    size = max(12, int(length))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(size))
        if (
            any(char.islower() for char in password)
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
            and any(char in "!@#$%^&*()-_=+" for char in password)
        ):
            return password


def _persist_signup_password(settings: Settings, email: str, signup_password: str) -> None:
    if not str(email or "").strip() or not str(signup_password or "").strip():
        return
    try:
        MailboxStore(settings.data_dir).update_signup_password(email.strip(), signup_password)
    except Exception as exc:
        logging.getLogger(__name__).warning(
            "[Codex] 注册密码落盘失败（%s）", type(exc).__name__
        )


_OTP_CONSUMED_FILENAME = "otp_consumed.json"
# 一次性验证码用完即弃，只需短期防复用即可；过期条目自动清理。
_OTP_CONSUMED_TTL_SECONDS = 6 * 3600
_OTP_CONSUMED_MAX_PER_EMAIL = 20


def _otp_consumed_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / _OTP_CONSUMED_FILENAME


def _load_otp_consumed_store(settings: Settings) -> dict:
    try:
        data = json.loads(_otp_consumed_path(settings).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _otp_entry_alive(item, now: float) -> bool:
    if not isinstance(item, dict):
        return False
    if not str(item.get("code") or "").strip():
        return False
    try:
        ts = float(item.get("ts") or 0)
    except (TypeError, ValueError):
        return False
    return 0 < ts and (now - ts) <= _OTP_CONSUMED_TTL_SECONDS


def _consumed_otps_for(settings: Settings, email: str) -> list[str]:
    """返回该邮箱近期已提交过、尚未过期的一次性验证码。"""
    key = str(email or "").strip().casefold()
    if not key:
        return []
    now = time.time()
    entries = _load_otp_consumed_store(settings).get(key) or []
    return [
        str(item["code"]).strip()
        for item in entries
        if _otp_entry_alive(item, now)
    ]


def _record_consumed_otp(settings: Settings, email: str, code: str) -> None:
    """记录一枚刚提交的一次性验证码，供后续轮次排除，避免复用旧码。"""
    key = str(email or "").strip().casefold()
    code = str(code or "").strip()
    if not key or not code:
        return
    now = time.time()
    store = _load_otp_consumed_store(settings)
    entries = [item for item in (store.get(key) or []) if _otp_entry_alive(item, now)]
    if not any(str(item.get("code") or "").strip() == code for item in entries):
        entries.append({"code": code, "ts": now})
    store[key] = entries[-_OTP_CONSUMED_MAX_PER_EMAIL:]
    try:
        path = _otp_consumed_path(settings)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(store, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "[Codex] 记录已用验证码失败（%s）", type(exc).__name__
        )


def _wait_for_email_otp(logger, otp_provider, email: str, *, after_ts: float, settings: Settings | None = None) -> str:
    email_otp = None
    # 一次性验证码用完即弃，复用旧码必然被判"代码不正确"。把此前已提交过的
    # 验证码作为排除项传给取码器，避免快速重试/背靠背取码时又抓到上一轮的旧码。
    track_consumed = settings is not None and bool(
        getattr(otp_provider, "supports_exclude_codes", False)
    )
    provider_kwargs: dict = {}
    if track_consumed:
        exclude_codes = _consumed_otps_for(settings, email)
        if exclude_codes:
            provider_kwargs["exclude_codes"] = exclude_codes
            logger.info("[Codex] 已排除 %d 枚近期用过的旧验证码", len(exclude_codes))
    try:
        max_email_otp_attempts = int(
            getattr(otp_provider, "codex_max_email_otp_attempts", 3) or 3
        )
    except (TypeError, ValueError):
        max_email_otp_attempts = 3
    max_email_otp_attempts = max(1, min(max_email_otp_attempts, 3))
    otp_after_ts = float(after_ts)
    for email_otp_attempt in range(1, max_email_otp_attempts + 1):
        logger.info(f"[Codex] 等待邮箱 OTP（第 {email_otp_attempt}/{max_email_otp_attempts} 次）")
        try:
            email_otp = otp_provider(email, after_ts=otp_after_ts, **provider_kwargs)
            break
        except Exception as exc:
            if email_otp_attempt >= max_email_otp_attempts:
                raise
            logger.warning(
                "[Codex] 一直未收到邮箱 OTP，当前活动页重新提交邮箱触发重发（下一轮 %s/%s）：%s: %s",
                email_otp_attempt + 1,
                max_email_otp_attempts,
                type(exc).__name__,
                str(exc)[:180],
            )
            otp_after_ts = time.time()
            _bridge_page_action("submit_email", email=email)
    if not email_otp:
        raise RuntimeError("[Codex] 未收到有效邮箱 OTP")
    email_otp = str(email_otp).strip()
    if track_consumed:
        # 记下这枚已提交的一次性验证码，供本账号后续轮次排除，杜绝复用旧码。
        _record_consumed_otp(settings, email, email_otp)
    return email_otp


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _load_runtime_environment(settings: Settings) -> None:
    for key, value in SAFE_DEFAULTS.items():
        os.environ.setdefault(key, value)
    env_path = settings.project_root / ".env"
    if env_path.is_file():
        for key, value in dotenv_values(env_path).items():
            if key and value is not None:
                os.environ[str(key)] = str(value)
    # Hero SMS is the only supported provider in this login-only project.
    # Force the protocol/login-only selectors after loading .env so stale
    # settings or inherited variables cannot route a job to an unbundled
    # browser or registration-oriented driver.
    os.environ["CODEX_OAUTH_DRIVER"] = "protocol"
    os.environ["SMS_PROVIDER"] = "hero"
    os.environ["SMS_SERVICE"] = "dr"
    os.environ.pop("SMS_PROVIDER_ORDER", None)


def _ensure_upstream_imports(settings: Settings):
    upstream_root = resolve_upstream_root(settings.project_root)
    if not (upstream_root / "core" / "codex_oauth.py").is_file():
        raise RuntimeError(f"未找到原项目 Codex OAuth 模块: {upstream_root}")
    root_text = str(upstream_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)

    _load_runtime_environment(settings)
    import config as upstream_config

    upstream_config.reload_all()
    from core import codex_oauth

    # 原模块只用该根目录决定 Codex 凭证/回执的保存位置。
    # 重定向到当前 login-only 项目的 data/，不污染原项目数据。
    codex_oauth._PROJECT_ROOT = settings.data_dir
    return codex_oauth


def _outlook_otp_provider(mailbox: dict) -> tuple[Callable, Callable[[], None]]:
    from core import outlook_client

    email = str(mailbox["email"])
    account = outlook_client.OutlookAccount(
        email=email,
        password=str(mailbox.get("password") or ""),
        client_id=str(mailbox.get("client_id") or ""),
        refresh_token=str(mailbox.get("refresh_token") or ""),
    )
    outlook_client._CONTEXT_CACHE[email] = account

    def get_otp(target_email: str, after_ts: float, **kwargs) -> str:
        if target_email.casefold() != email.casefold():
            raise RuntimeError("OTP 请求邮箱与已导入账号不一致")
        return outlook_client.fetch_latest_otp(target_email, after_ts=after_ts, **kwargs)

    def cleanup() -> None:
        outlook_client._CONTEXT_CACHE.pop(email, None)

    return get_otp, cleanup


def _generic_api_otp_provider(mailbox: dict) -> tuple[Callable, Callable[[], None]]:
    from core import generic_api_mail_client

    email = str(mailbox["email"])
    account = generic_api_mail_client.GenericApiEmailAccount(
        email=email,
        code_url=str(mailbox.get("code_url") or ""),
    )
    generic_api_mail_client._CONTEXT_CACHE[email] = account

    def get_otp(target_email: str, after_ts: float, **kwargs) -> str:
        if target_email.casefold() != email.casefold():
            raise RuntimeError("OTP 请求邮箱与已导入账号不一致")
        # 取码页的邮件到达常比 30 秒更慢。使用独立可配置窗口，
        # 避免全局 OTP 参数较短时过早判定失败。
        kwargs["max_wait"] = _bounded_env_int(
            "GENERIC_API_OTP_MAX_WAIT",
            GENERIC_API_OTP_MAX_WAIT_SECONDS,
            30,
            300,
        )
        kwargs.setdefault(
            "poll_interval",
            _bounded_env_int(
                "GENERIC_API_OTP_POLL_INTERVAL",
                GENERIC_API_OTP_POLL_INTERVAL_SECONDS,
                1,
                30,
            ),
        )
        return generic_api_mail_client.fetch_latest_otp(target_email, after_ts=after_ts, **kwargs)

    # 上游协议默认会重发邮箱并连续等待三轮。通用 API 取码超时后直接结束，
    # 后续是否重新跑整个账号由流水线的“失败重试”设置决定。
    get_otp.codex_max_email_otp_attempts = 1
    # 通用 API 取码器支持排除已用过的一次性验证码（见 fetch_latest_otp）。
    get_otp.supports_exclude_codes = True

    def cleanup() -> None:
        generic_api_mail_client._CONTEXT_CACHE.pop(email, None)

    return get_otp, cleanup


_bridge_context = threading.local()


def _current_bridge_tab() -> int | None:
    return getattr(_bridge_context, "tab_id", None)


@contextmanager
def _bridge_tab(tab_id: int | None):
    """Pin every bridge request inside the block to one specific browser tab.

    gcash 提炼 drives two fixed tabs (ChatGPT login + 153 提炼) in one run, so the
    historical "act on whatever tab is active" behaviour is not enough. Setting
    the target here means every existing helper (``_login_account_in_browser`` &
    friends) works unchanged inside the block. Thread-local because pipeline
    workers are threads in one process; outside any block the value is None and
    the extension falls back to the active tab exactly as before.
    """
    previous = getattr(_bridge_context, "tab_id", None)
    _bridge_context.tab_id = None if tab_id is None else int(tab_id)
    try:
        yield
    finally:
        _bridge_context.tab_id = previous


def _bridge_request(
    kind: str, payload: dict, *, timeout: float = 120.0, raise_on_error: bool = True
) -> dict:
    target_tab = _current_bridge_tab()
    if target_tab is not None and "tab_id" not in payload:
        payload = {**payload, "tab_id": target_tab}
    try:
        result = browser_bridge.request(kind, payload, timeout=timeout)
    except BrowserBridgeTimeout as exc:
        raise RuntimeError(str(exc)) from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"浏览器桥返回了无效响应：{kind}")
    if result.get("ok") is False and not raise_on_error:
        # Caller wants to inspect the structured failure (e.g. needs_phone_page)
        # rather than have it raised. Return the raw result untouched.
        return result
    if result.get("ok") is False:
        error = str(result.get("error") or result.get("error_text") or "浏览器桥执行失败")
        state = result.get("state") if isinstance(result.get("state"), dict) else {}
        snapshot = result.get("snapshot") if isinstance(result.get("snapshot"), dict) else {}
        logger = logging.getLogger(__name__)
        if snapshot:
            logger.warning(
                "[BridgeDOM] kind=%s unknown_page=%s url=%s title=%s",
                kind,
                bool(result.get("unknown_page")),
                str(snapshot.get("url") or state.get("url") or ""),
                str(snapshot.get("title") or state.get("title") or ""),
            )
            for key in ("headings", "buttons", "inputs"):
                value = snapshot.get(key)
                if value:
                    logger.warning(
                        "[BridgeDOM] %s=%s",
                        key,
                        json.dumps(value, ensure_ascii=False),
                    )
            body_text = str(snapshot.get("body_text") or "").strip()
            if body_text:
                logger.warning("[BridgeDOM] body_text=%s", body_text[:4000])
            body_html = str(snapshot.get("body_html") or "").strip()
            if body_html:
                logger.warning("[BridgeDOM] body_html=%s", body_html[:12000])
        # Dead-account safety net: OpenAI's 身份验证错误 / account_deactivated
        # screen means the email itself is unusable (deleted/deactivated).
        # Detect it straight from the page snapshot — even when the extension
        # did not tag it — and stamp the account_deactivated token so the
        # scheduler ends the job as a dead account instead of a plain failure.
        haystack = " ".join(
            str(part or "")
            for part in (
                error,
                snapshot.get("title"),
                snapshot.get("body_text"),
                " ".join(map(str, snapshot.get("headings") or [])),
                state.get("title"),
                state.get("body_preview"),
            )
        )
        if "account_deactivated" not in error and any(
            marker in haystack
            for marker in ("account_deactivated", "已被删除或停用", "账户已被删除")
        ):
            error = f"账号不可用 account_deactivated：{error}"
        where = str(state.get("url") or "")
        if where:
            raise RuntimeError(f"{error} @ {where}")
        raise RuntimeError(error)
    return result


_ABOUT_YOU_FIRST_NAMES = (
    "James", "Michael", "Robert", "David", "William", "Joseph", "Daniel",
    "Emily", "Olivia", "Emma", "Sophia", "Ava", "Grace", "Chloe",
    "Ethan", "Ryan", "Nathan", "Lucas", "Henry", "Owen", "Julian",
)
_ABOUT_YOU_LAST_NAMES = (
    "Smith", "Johnson", "Brown", "Taylor", "Anderson", "Thomas", "Walker",
    "Harris", "Clark", "Lewis", "Young", "Hall", "Allen", "Wright",
    "Carter", "Mitchell", "Parker", "Evans", "Turner", "Collins", "Bennett",
)


def _generate_about_you_profile() -> tuple[str, int]:
    """Return a plausible (full_name, age) for the final /about-you onboarding page."""
    first = secrets.choice(_ABOUT_YOU_FIRST_NAMES)
    last = secrets.choice(_ABOUT_YOU_LAST_NAMES)
    age = 24 + secrets.randbelow(22)  # 24..45 inclusive
    return f"{first} {last}", age


def _bridge_navigate(url: str, *, timeout: float = 90.0, retries: int = 2) -> dict:
    # A navigate that times out never completed, so re-issuing the same GET is
    # safe. Chrome MV3 service workers go idle and can miss the first request,
    # and the cold Cloudflare challenge on the first chatgpt.com/login load (esp.
    # right after a full cookie wipe) can exceed the tab-load window; a couple of
    # retries let a transient stall self-recover instead of killing the job.
    last_exc: RuntimeError | None = None
    for attempt in range(retries + 1):
        try:
            return _bridge_request("navigate", {"url": url}, timeout=timeout)
        except RuntimeError as exc:
            if "超时" not in str(exc) or attempt >= retries:
                raise
            last_exc = exc
            logging.getLogger(__name__).warning(
                "[Codex] 导航超时（%s），浏览器桥可能休眠，重试第 %d 次：%s",
                url,
                attempt + 1,
                exc,
            )
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"浏览器桥导航失败：{url}")


def _bridge_page_action(action: str, **payload) -> dict:
    timeout = float(payload.pop("timeout", 120.0))
    raise_on_error = bool(payload.pop("raise_on_error", True))
    return _bridge_request(
        "page_action",
        {"action": action, **payload},
        timeout=timeout,
        raise_on_error=raise_on_error,
    )


_CLEANUP_ORIGINS = (
    "https://chatgpt.com",
    "https://auth.openai.com",
    "https://openai.com",
    "https://platform.openai.com",
)


def _bridge_cleanup(*, timeout: float = 60.0) -> dict:
    """Wipe openai/chatgpt cookies, cache, storage & service workers before an
    account starts. In a serial pipeline the previous account's session must NOT
    leak into the next one — otherwise OpenAI shows /choose-an-account or reuses a
    stale consent verifier. Runs synchronously via the bridge so it always
    completes before the login navigation, unlike the sidepanel's poll-driven
    post-job cleanup (which can lag behind the next worker starting)."""
    logger = logging.getLogger(__name__)
    try:
        result = _bridge_request(
            "cleanup", {"origins": list(_CLEANUP_ORIGINS)}, timeout=timeout, raise_on_error=False
        )
    except RuntimeError as exc:
        logger.warning("[Codex] 账号开始前清理浏览器失败：%s", exc)
        return {"ok": False}
    if not result.get("ok"):
        logger.warning("[Codex] 账号开始前清理浏览器返回失败：%s", result.get("error") or "")
    return result


def _bridge_page_fetch(url: str, *, timeout: float = 60.0) -> dict:
    """Fetch a URL from inside the active tab (cookies included) via the bridge.

    Used to read chatgpt.com/api/auth/session with the just-logged-in browser
    session, which a plain server-side request could not do."""
    return _bridge_request(
        "page_fetch",
        {"url": url, "method": "GET", "credentials": "include"},
        timeout=timeout,
        raise_on_error=False,
    )


def _browser_flow_available() -> bool:
    return browser_bridge.client_recently_seen(within_seconds=120)


def _sms_slot_count() -> int:
    """Total (channel × country) combinations to attempt before接码 fails.

    Replaces the old fixed SMS_MAX_RETRIES: the phone loop now walks every
    configured country on every enabled channel exactly once — the per-channel
    cursor rotates to a fresh country on each acquisition — and only reports
    接码 failure after all channels and countries have been tried.
    """
    from .sms_config import normalize_hero_countries

    total = 0
    try:
        total += len(normalize_hero_countries(os.getenv("HERO_SMS_COUNTRIES", "")))
    except ValueError:
        pass
    if str(os.getenv("SMSBOWER_API_KEY", "") or "").strip():
        try:
            total += len(normalize_hero_countries(os.getenv("SMSBOWER_COUNTRIES", "")))
        except ValueError:
            pass
    return max(total, 1)


def _advance_past_create_account_password(settings: Settings, email: str, signup_password: str, logger) -> tuple[float, str]:
    """Newer signup flow lands on ``create-account/password`` *before* any OTP
    email is sent. Switch to the one-time-code registration (CDP trusted click)
    so the OTP email is actually triggered; if passwordless signup is disabled,
    fall back to setting a password. Returns ``(after_ts, stage)`` where
    ``after_ts`` is the moment the OTP was requested and ``stage`` is the page
    reached afterwards."""
    otp_after_ts = time.time()
    passwordless_result = _bridge_page_action("activate_passwordless_signup")
    if str(passwordless_result.get("error_text") or "").strip():
        raise RuntimeError(
            f"[Codex] 一次性验证码注册切换失败：{str(passwordless_result.get('error_text') or '')[:240]}"
        )
    if passwordless_result.get("passwordless_disabled"):
        logger.info("[Codex] 当前环境禁用无密码注册，改为自动设置密码继续")
        _persist_signup_password(settings, email, signup_password)
        otp_after_ts = time.time()
        signup_password_result = _bridge_page_action(
            "submit_signup_password",
            password=signup_password,
        )
        if signup_password_result.get("used_signup_password"):
            logger.info("[Codex] 已自动提交注册密码继续")
        if str(signup_password_result.get("error_text") or "").strip():
            raise RuntimeError(
                f"[Codex] 自动设置密码后继续失败：{str(signup_password_result.get('error_text') or '')[:240]}"
            )
        stage = str(signup_password_result.get("next_stage") or "").strip().lower()
    else:
        stage = str(
            passwordless_result.get("next_stage")
            or passwordless_result.get("stage")
            or ""
        ).strip().lower()
    logger.info("[Codex] 设置密码页处理后进入阶段：%s", stage or "unknown")
    return otp_after_ts, stage


def _save_session_payload(settings: Settings, email: str, session: dict, logger) -> str | None:
    """Write a session payload to data/codex_sessions/{YYYY-MM-DD}/session-{email}.json."""
    day = time.strftime("%Y-%m-%d")
    out_dir = Path(settings.data_dir) / "codex_sessions" / day
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_email = re.sub(r"[^A-Za-z0-9._@+-]", "_", email) or "unknown"
    path = out_dir / f"session-{safe_email}.json"
    path.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logger.info("[Codex] Session 已保存：%s", path)
    return str(path)


def _capture_and_save_session(settings: Settings, email: str, logger) -> str | None:
    """Fetch chatgpt.com/api/auth/session with the live browser session and save
    it to data/codex_sessions/{YYYY-MM-DD}/session-{email}.json. Returns the path
    string on success, else None (never raises — session export is best-effort)."""
    try:
        # A short settle helps the just-finished OAuth cookies propagate to
        # chatgpt.com before we read the session.
        _bridge_navigate("https://chatgpt.com/", timeout=60.0)
    except RuntimeError as exc:
        logger.warning("[Codex] 打开 chatgpt.com 以读取 Session 失败：%s", exc)
    result = _bridge_page_fetch("https://chatgpt.com/api/auth/session")
    if not result.get("ok"):
        logger.warning("[Codex] 读取 Session 失败：%s", str(result.get("error") or "")[:200])
        return None
    status = int(result.get("status") or 0)
    body = str(result.get("body") or "")
    if status != 200 or not body.strip():
        logger.warning("[Codex] Session 接口返回异常 status=%s body=%s", status, body[:200])
        return None
    parsed = _parse_session_body(body)
    if parsed is None:
        logger.warning("[Codex] Session 响应为空或不是已登录 JSON，未保存")
        return None
    return _save_session_payload(settings, email, parsed, logger)


_FRAME_TEARDOWN_ERROR = re.compile(
    r"Frame with ID \d+ was removed|No frame with id|No tab with id"
    r"|Target closed|context was destroyed|页面动作返回空结果",
    re.IGNORECASE,
)


def _is_frame_teardown_error(exc: BaseException | str) -> bool:
    """A submit whose injected frame died is almost always a submit that WORKED.

    The page navigates away (login → chatgpt.com) and tears the injection frame
    down before ``executeScript`` can return, so the bridge reports
    "Frame with ID X was removed" for a step that actually succeeded. Callers
    must confirm the real outcome instead of failing the job outright
    (same class of trap as the OAuth finalize step)."""
    return bool(_FRAME_TEARDOWN_ERROR.search(str(exc)))


def _parse_session_body(body: str) -> dict | None:
    """Return the parsed chatgpt.com/api/auth/session payload if it shows a
    logged-in user; ``None`` for the ``{}`` that a signed-out browser gets."""
    try:
        parsed = json.loads(str(body or ""))
    except ValueError:
        return None
    if not isinstance(parsed, dict) or not parsed:
        return None
    if parsed.get("user") or parsed.get("accessToken") or parsed.get("access_token"):
        return parsed
    return None


def _confirm_logged_in(logger, *, label: str, timeout: float = 90.0) -> dict | None:
    """Poll chatgpt.com/api/auth/session through the active tab until it reports
    a logged-in user. Returns the session payload, or ``None`` on timeout.

    ``page_fetch`` runs inside the active page, so the tab has to be on
    chatgpt.com for the request to carry cookies (a cross-origin read from
    auth.openai.com is blocked). Try in place first — right after login the tab
    is usually already redirecting there — and navigate only if that fails.
    """
    deadline = time.time() + timeout
    navigated = False
    while True:
        try:
            result = _bridge_page_fetch("https://chatgpt.com/api/auth/session")
        except RuntimeError as exc:
            logger.debug("[Codex] %s：读取 session 接口失败：%s", label, str(exc)[:160])
            result = {}
        if result.get("ok") and int(result.get("status") or 0) == 200:
            session = _parse_session_body(str(result.get("body") or ""))
            if session is not None:
                return session
        if time.time() >= deadline:
            return None
        if not navigated:
            # Park the tab on chatgpt.com so the in-page fetch is same-origin.
            navigated = True
            try:
                _bridge_navigate("https://chatgpt.com/", timeout=60.0)
            except RuntimeError as exc:
                logger.warning("[Codex] %s：打开 chatgpt.com 确认登录态失败：%s", label, str(exc)[:160])
        time.sleep(3.0)


def _submit_login_step(action: str, *, label: str, step: str, logger, **payload) -> dict:
    """Run a login page action, tolerating the injection frame being torn down.

    Returns the bridge result, or ``{"frame_teardown": True}`` when the frame
    died mid-navigation — the caller then confirms the outcome via the session
    endpoint instead of treating it as a failure."""
    try:
        return _bridge_page_action(action, **payload)
    except RuntimeError as exc:
        if not _is_frame_teardown_error(exc):
            raise
        logger.info(
            "[Codex] %s：%s 后注入帧被销毁（页面正在跳转），改用 session 接口确认结果：%s",
            label,
            step,
            str(exc)[:160],
        )
        return {"ok": True, "frame_teardown": True, "error_text": "", "teardown_error": str(exc)}


def _login_account_in_browser(
    settings: Settings,
    mailbox: dict,
    *,
    otp_provider,
    password: str = "",
    totp_provider=None,
    label: str = "登录",
) -> tuple[object, str]:
    """Log the account into ChatGPT (email + email OTP, or password + TOTP).

    This does NOT run the Codex OAuth authorize flow — no phone verification, no
    consent, no SMS. Returns ``(codex_oauth_module, email)`` once the account is
    logged in; raises on any failure.
    """
    codex_oauth = _ensure_upstream_imports(settings)
    logger = codex_oauth.logger
    email = str(mailbox.get("email") or "").strip()
    source = str(mailbox.get("source") or "").strip().lower()
    password_totp_login = source == "password_totp"

    logger.info("[Codex] %s：账号开始前清理浏览器（保持隐私模式）", label)
    _bridge_cleanup()
    # After a cookie wipe, auth.openai.com/log-in shows a "你的会话已结束"
    # interstitial with only a "登录" link (no email form). The real email-entry
    # page is reached via chatgpt.com/auth/login_with, which mints the session
    # context first. Go straight there — loading the heavy chatgpt.com SPA root
    # first only risks a 45s "标签页加载超时" without helping.
    _bridge_navigate("https://chatgpt.com/auth/login_with?callback_path=/")
    time.sleep(2.0)

    # /auth/login_with is a redirect endpoint that bounces through several hops
    # before the email form settles; submit_email can inject into a frame that is
    # torn down mid-redirect ("Frame with ID X was removed"). Retry a few times —
    # once the redirect chain settles the email form is there.
    email_result = None
    for submit_attempt in range(1, 6):
        try:
            email_result = _bridge_page_action("submit_email", email=email)
            break
        except RuntimeError as exc:
            msg = str(exc)
            transient = _is_frame_teardown_error(msg) or bool(re.search(r"标签页加载超时|超时", msg))
            if not transient or submit_attempt >= 5:
                raise
            logger.warning("[Codex] %s：登录页仍在跳转，2s 后重试提交邮箱（第 %d 次）：%s", label, submit_attempt + 1, msg[:120])
            time.sleep(2.0)
    if email_result is None:
        raise RuntimeError(f"[Codex] {label}：未能进入邮箱登录页")
    email_stage = str(email_result.get("next_stage") or "").strip().lower()
    logger.info("[Codex] %s：提交邮箱后进入阶段：%s", label, email_stage or "unknown")

    if password_totp_login:
        if not password or not callable(totp_provider):
            raise ValueError("密码 + TOTP 账号缺少密码或 TOTP 提供器")
        password_result = _submit_login_step(
            "submit_password", label=label, step="提交密码", logger=logger, password=password
        )
        if str(password_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] 密码验证失败：{str(password_result.get('error_text') or '')[:240]}")
        if password_result.get("frame_teardown"):
            # The MFA page is a fresh document; give it a moment to settle before
            # injecting the TOTP step into it.
            time.sleep(2.0)
        time.sleep(0.5)
        mfa_result = _submit_login_step(
            "submit_mfa_totp",
            label=label,
            step="提交 TOTP 验证码",
            logger=logger,
            code=str(totp_provider() or "").strip(),
        )
        if str(mfa_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] TOTP 2FA 验证失败：{str(mfa_result.get('error_text') or '')[:240]}")
        last_teardown = str(mfa_result.get("teardown_error") or "")
    else:
        # These accounts log in passwordless via a one-time email code. The login
        # page (not signup) should land straight on the email-verification step;
        # if it instead shows create-account/password, trigger the OTP first.
        otp_after_ts = time.time()
        if email_stage == "create-account-password":
            logger.info("[Codex] %s：登录进入设置密码页，先触发一次性验证码", label)
            otp_after_ts, advanced_stage = _advance_past_create_account_password(
                settings, email, "", logger
            )
        email_otp = _wait_for_email_otp(logger, otp_provider, email, after_ts=otp_after_ts, settings=settings)
        logger.info("[Codex] %s：邮箱 OTP 已收到", label)
        email_otp_result = _submit_login_step(
            "submit_email_otp", label=label, step="提交邮箱验证码", logger=logger, code=email_otp
        )
        if str(email_otp_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] 邮箱 OTP 验证失败：{str(email_otp_result.get('error_text') or '')[:240]}")
        last_teardown = str(email_otp_result.get("teardown_error") or "")

    # The page actions above are driven for the OAuth flow, where the step after
    # the OTP is the phone page — on this login-only path OpenAI instead jumps
    # straight to chatgpt.com, which kills the injected frame. So the single
    # source of truth for "did the login work" is the session endpoint.
    session = _confirm_logged_in(logger, label=label)
    if session is None:
        if last_teardown:
            raise RuntimeError(
                f"[Codex] {label}：提交后页面跳转但未确认登录态（{last_teardown[:160]}）"
            )
        raise RuntimeError(f"[Codex] {label}：登录流程结束但 chatgpt.com 仍未处于登录状态")
    logger.info("[Codex] %s：已确认 %s 处于登录状态", label, email)
    return codex_oauth, email, session


def _run_session_export(settings: Settings, mailbox: dict, *, otp_provider, password: str = "", totp_provider=None) -> dict:
    """Session-only path: log the account into ChatGPT, then read
    chatgpt.com/api/auth/session with the live cookies (no OAuth, no SMS)."""
    codex_oauth, email, session = _login_account_in_browser(
        settings,
        mailbox,
        otp_provider=otp_provider,
        password=password,
        totp_provider=totp_provider,
        label="Session 导出",
    )
    # The session payload from _confirm_logged_in is already the fresh
    # chatgpt.com/api/auth/session — save it directly instead of fetching again.
    if session:
        session_path = _save_session_payload(settings, email, session, codex_oauth.logger)
    else:
        session_path = _capture_and_save_session(settings, email, codex_oauth.logger)
    if not session_path:
        raise RuntimeError("[Codex] 已登录但读取 chatgpt.com/api/auth/session 失败")
    return codex_oauth._codex_result(
        status="success",
        ok=True,
        email=email,
        file_path=session_path,
        message="Session 已导出",
    )


def _run_login_only(settings: Settings, mailbox: dict, *, otp_provider, password: str = "", totp_provider=None) -> dict:
    """Login-only path: just sign the selected account into chatgpt.com and stop.

    No session capture, no Codex OAuth authorize, no phone verification, no SMS —
    the browser is simply left on a logged-in chatgpt.com for manual follow-up.
    """
    codex_oauth, email, _session = _login_account_in_browser(
        settings,
        mailbox,
        otp_provider=otp_provider,
        password=password,
        totp_provider=totp_provider,
        label="仅登录",
    )
    logger = codex_oauth.logger
    # Deliberately no extra navigation here: the browser is already sitting on
    # the post-login page and OpenAI finishes the redirect to chatgpt.com on its
    # own. Re-issuing a navigate only risks a "标签页加载超时" and can race with
    # the tab being parked on about:blank. Just let the redirect settle.
    time.sleep(2.0)
    logger.info("[Codex] 仅登录：%s 已完成登录，浏览器保持登录态", email)
    return codex_oauth._codex_result(
        status="success",
        ok=True,
        email=email,
        message="已登录 ChatGPT（仅登录模式，未导出 Session、未走 OAuth）",
    )


_GCASH_TOKEN_URL = "https://chatgpt.com/api/auth/session"
_GCASH_START_TIMEOUT = 60.0
_GCASH_RUN_TIMEOUT = 1200.0
_GCASH_POLL_SECONDS = 3.0
_GCASH_FAILED_TOKEN = "gcash_extract_failed"
_GCASH_PAYMENT_HOSTS = re.compile(r"^https?://([^/]*\.)?(m\.gcash\.com|gcash\.com|checkoutshopper[^/]*\.adyen\.com)", re.I)
_GCASH_RETURN_URL = re.compile(r"^https?://([^/]*\.)?chatgpt\.com(/|$)", re.I)


def _extract_access_token(session: object) -> str:
    if not isinstance(session, dict):
        return ""
    for key in ("accessToken", "access_token"):
        value = str(session.get(key) or "").strip()
        if value:
            return value
    return ""


def _read_gcash_access_token(logger, session: dict | None) -> str:
    """Resolve the account's accessToken from chatgpt.com/api/auth/session.

    ``_login_account_in_browser`` already polls that exact endpoint to confirm
    the login, so its payload is the primary source. Re-reading it through the
    bridge (and finally rendering the endpoint in the tab) are fallbacks for the
    case where the confirmation payload came back without the token.
    """
    token = _extract_access_token(session)
    if token:
        return token
    result = _bridge_page_fetch(_GCASH_TOKEN_URL)
    if result.get("ok") and int(result.get("status") or 0) == 200:
        token = _extract_access_token(_parse_session_body(str(result.get("body") or "")))
        if token:
            return token
    logger.info("[gcash] 页面内读取 session 未拿到 accessToken，改为直接打开 %s", _GCASH_TOKEN_URL)
    try:
        _bridge_navigate(_GCASH_TOKEN_URL, timeout=60.0)
    except RuntimeError as exc:
        logger.warning("[gcash] 打开 session 接口失败：%s", str(exc)[:160])
        return ""
    snapshot = _bridge_page_action("snapshot_dom", timeout=45.0, raise_on_error=False)
    body = str((snapshot.get("snapshot") or {}).get("body_text") or "")
    return _extract_access_token(_parse_session_body(body))


def _gcash_probe(*, raise_on_error: bool = False) -> dict:
    return _bridge_page_action("gcash_probe", timeout=45.0, raise_on_error=raise_on_error)


def _gcash_percent(probe: dict) -> float:
    value = probe.get("percent")
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _gcash_state_key(probe: dict) -> tuple:
    """The fields that must change once 「开始提炼」 actually started a new run."""
    return (
        bool(probe.get("result_visible")),
        str(probe.get("result_session") or ""),
        str(probe.get("progress_stage") or ""),
        str(probe.get("progress_text") or ""),
        _gcash_percent(probe),
    )


_GCASH_TERMINAL_MARKERS = ("任务失败", "任务完成", "任务异常", "已完成", "失败", "异常", "完成")


def _gcash_terminal_state(probe: dict) -> bool:
    """The console announced a terminal state in plain text.

    The progress bar does not always reach 100% on a failed run — the captured
    log showed the page sitting on "任务异常 / 任务失败" while the bar stalled —
    so waiting only for ``percent >= 100`` burned the whole run budget before
    declaring the failure. The badge/text are the console's own verdicts.
    """
    haystack = " ".join(
        str(part or "")
        for part in (
            probe.get("progress_text"),
            probe.get("progress_stage"),
            probe.get("status_badge"),
        )
    )
    return any(marker in haystack for marker in _GCASH_TERMINAL_MARKERS)


def _wait_for_gcash_outcome(logger, baseline: dict) -> dict:
    """Wait for the 153 console to finish, then classify the run.

    Two signals decide the outcome, exactly as observed in the captured pages:
    the progress bar reaching 100%, and whether the 「提炼结果」 panel is shown.
    A failed run leaves the *previous* run's link inside a hidden #resultValue,
    so the panel's visibility — never the field's content — is what separates
    success from failure.
    """
    started = False
    start_deadline = time.time() + _GCASH_START_TIMEOUT
    run_deadline = time.time() + _GCASH_RUN_TIMEOUT
    last: dict = dict(baseline)
    baseline_key = _gcash_state_key(baseline)
    while True:
        probe = _gcash_probe()
        if probe.get("ok"):
            last = probe
            if not started:
                # Either the page reset for the new run, or it is visibly busy.
                if probe.get("running") or _gcash_state_key(probe) != baseline_key or _gcash_percent(probe) < 100:
                    started = True
                    logger.info(
                        "[gcash] 提炼任务已启动：stage=%s text=%s",
                        probe.get("progress_stage"),
                        probe.get("progress_text"),
                    )
            if started and not probe.get("running"):
                percent = _gcash_percent(probe)
                if percent >= 100 or _gcash_terminal_state(probe):
                    success = bool(probe.get("result_visible")) and bool(str(probe.get("result_value") or "").strip())
                    return {"success": success, "probe": probe}
        now = time.time()
        if not started and now >= start_deadline:
            raise RuntimeError(
                f"[Codex] {_GCASH_FAILED_TOKEN}：点击「开始提炼」后页面状态一直没有变化"
                f"（stage={last.get('progress_stage')} text={last.get('progress_text')}）"
            )
        if now >= run_deadline:
            raise RuntimeError(
                f"[Codex] {_GCASH_FAILED_TOKEN}：等待提炼结束超过 {int(_GCASH_RUN_TIMEOUT)} 秒仍未结束"
                f"（stage={last.get('progress_stage')} text={last.get('progress_text')}）"
            )
        time.sleep(_GCASH_POLL_SECONDS)


def _wait_for_gcash_scan(logger, *, cancel_event=None) -> tuple[bool, str, bool]:
    """Poll the login tab's own URL until the human finishes scanning.

    The payment link redirects the tab to m.gcash.com; a successful scan bounces
    it back to chatgpt.com. Requiring the payment host to be seen first means a
    navigation that never left chatgpt.com cannot be misread as a success.

    Scanning is a manual step with no fixed duration, so this waits indefinitely
    — there is no timeout. It exits early only when (a) the scan completes, (b)
    the bound tab disappears (operator closed it), or (c) ``cancel_event`` is set
    (user stopped the pipeline) — a worker thread can't be force-killed, so this
    cooperative check is what makes "stop" take effect during the long wait.

    Returns ``(scanned, last_url, stopped)``.
    """

    def _should_stop() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    entered_payment = False
    last_url = ""
    while True:
        if _should_stop():
            logger.info("[gcash] 收到停止请求，中断扫码等待")
            return False, last_url, True
        result = _bridge_request("tab_url", {}, timeout=30.0, raise_on_error=False)
        if result.get("ok") is False:
            error = str(result.get("error") or "")
            # A gone/unbound tab never comes back — stop instead of spinning
            # forever. Any other transient bridge hiccup: keep waiting.
            if "已不存在" in error or "无效的目标标签页" in error or "未找到当前活动标签页" in error:
                logger.info("[gcash] 等待扫码时登录标签页已失效：%s", error[:200])
                return False, last_url, False
            if _should_stop():
                return False, last_url, True
            time.sleep(_GCASH_POLL_SECONDS)
            continue
        url = str(result.get("url") or "")
        if url and url != last_url:
            logger.info("[gcash] 支付页当前地址：%s", url[:200])
            last_url = url
        if _GCASH_PAYMENT_HOSTS.match(url):
            entered_payment = True
        elif url and not _GCASH_RETURN_URL.match(url) and not url.startswith("about:"):
            # Any third-party hop (bank/redirector) also counts as "left ChatGPT".
            entered_payment = True
        if entered_payment and _GCASH_RETURN_URL.match(url):
            return True, url, False
        if _should_stop():
            logger.info("[gcash] 收到停止请求，中断扫码等待")
            return False, last_url, True
        time.sleep(_GCASH_POLL_SECONDS)


def _run_gcash_extraction(
    settings: Settings, mailbox: dict, *, otp_provider, password: str = "", totp_provider=None, cancel_event=None
) -> dict:
    """gcash 提炼: login in one bound tab, extract a payment link in the other.

    Tab 1 (「ChatGPT登录」) runs the plain login and yields the accessToken;
    tab 2 (「153提炼」) turns that token into a GCash payment link; the link then
    goes back into tab 1 for the operator to scan.
    """
    codex_oauth = _ensure_upstream_imports(settings)
    logger = codex_oauth.logger
    login_tab = mailbox.get("gcash_login_tab_id")
    extract_tab = mailbox.get("gcash_extract_tab_id")
    if not isinstance(login_tab, int) or not isinstance(extract_tab, int):
        raise RuntimeError(
            f"[Codex] {_GCASH_FAILED_TOKEN}：未绑定标签页，请先在插件「调试」页绑定「ChatGPT登录」和「153提炼」两个标签页"
        )
    if login_tab == extract_tab:
        raise RuntimeError(f"[Codex] {_GCASH_FAILED_TOKEN}：两个标签页不能绑定成同一个")
    store = MailboxStore(settings.data_dir)

    with _bridge_tab(login_tab):
        _codex_oauth, email, session = _login_account_in_browser(
            settings,
            mailbox,
            otp_provider=otp_provider,
            password=password,
            totp_provider=totp_provider,
            label="gcash提炼·登录",
        )
        access_token = _read_gcash_access_token(logger, session)
    if not access_token:
        raise RuntimeError(f"[Codex] {_GCASH_FAILED_TOKEN}：已登录但未能取到 accessToken")
    store.update_gcash(email, access_token=access_token, status="running", message="已登录并取到 accessToken")
    logger.info("[gcash] %s 已取到 accessToken（%d 字符），切到 153 提炼标签页", email, len(access_token))

    with _bridge_tab(extract_tab):
        baseline = _gcash_probe()
        if not baseline.get("ok") or not baseline.get("page_ready"):
            raise RuntimeError(
                f"[Codex] {_GCASH_FAILED_TOKEN}：绑定的「153提炼」标签页不是提炼页"
                f"（{baseline.get('error') or baseline.get('tab_url') or '未知页面'}）"
            )
        submitted = _bridge_page_action("gcash_submit", token=access_token, timeout=60.0, raise_on_error=False)
        if not submitted.get("ok"):
            raise RuntimeError(f"[Codex] {_GCASH_FAILED_TOKEN}：{submitted.get('error') or '提交提炼失败'}")
        logger.info("[gcash] 已填入 accessToken 并点击「开始提炼」，开始等待运行结果")
        outcome = _wait_for_gcash_outcome(logger, baseline)

    probe = outcome["probe"]
    if not outcome["success"]:
        reason = str(probe.get("progress_text") or probe.get("progress_stage") or "页面未产出提炼结果").strip()
        tail = " | ".join(str(item) for item in (probe.get("log_tail") or [])[-2:])
        message = f"gcash 提炼失败：{reason}" + (f"（{tail[:300]}）" if tail else "")
        store.update_gcash(email, status="failed", message=message)
        logger.warning("[gcash] %s 提炼失败：%s", email, message)
        return codex_oauth._codex_result(
            status="failed", ok=False, email=email, message=f"{_GCASH_FAILED_TOKEN}：{message}"
        )

    link = str(probe.get("result_value") or "").strip() or str(probe.get("result_link") or "").strip()
    if not link:
        store.update_gcash(email, status="failed", message="提炼结果区域已出现但最终链接为空")
        return codex_oauth._codex_result(
            status="failed", ok=False, email=email,
            message=f"{_GCASH_FAILED_TOKEN}：提炼结果区域已出现但「最终链接 / 付款码」为空",
        )
    store.update_gcash(email, link=link, message="已拿到付款链接，等待扫码")
    logger.info("[gcash] %s 已拿到付款链接，切回登录标签页等待扫码", email)

    with _bridge_tab(login_tab):
        try:
            _bridge_navigate(link, timeout=90.0, retries=0)
        except RuntimeError as exc:
            # The payment link redirects through third parties; a slow load is
            # normal and the URL watcher below is the real source of truth.
            logger.info("[gcash] 打开付款链接时标签页未报告加载完成（继续监控地址）：%s", str(exc)[:160])
        scanned, final_url, stopped = _wait_for_gcash_scan(logger, cancel_event=cancel_event)

    if stopped:
        message = "用户已停止流水线，扫码等待中断"
        store.update_gcash(email, message=message)
        logger.info("[gcash] %s %s", email, message)
        return codex_oauth._codex_result(
            status="stopped", ok=False, email=email, message=message
        )
    if not scanned:
        message = f"付款链接已打开但未等到扫码完成（最后地址：{final_url[:200] or '未知'}）"
        store.update_gcash(email, status="failed", message=message)
        return codex_oauth._codex_result(
            status="failed", ok=False, email=email, message=f"{_GCASH_FAILED_TOKEN}：{message}"
        )
    store.update_gcash(email, status="success", message=f"扫码完成，已跳回 {final_url[:200]}")
    logger.info("[gcash] %s 提炼成功，扫码后已跳回 %s", email, final_url[:200])
    return codex_oauth._codex_result(
        status="success", ok=True, email=email, callback_url=final_url, message="gcash 提炼成功"
    )


def _run_codex_in_browser(settings: Settings, mailbox: dict, *, otp_provider, password: str = "", totp_provider=None) -> dict:
    codex_oauth = _ensure_upstream_imports(settings)
    logger = codex_oauth.logger
    email = str(mailbox.get("email") or "").strip()
    source = str(mailbox.get("source") or "").strip().lower()
    password_totp_login = source == "password_totp"
    signup_password = "" if password_totp_login else _generate_signup_password()
    session = codex_oauth.BrowserSession(proxy=None)
    logger.info("[Codex] 开始授权（当前活动页浏览器模式）")

    auth_source = codex_oauth._codex_auth_url_source()
    cpa_auth = None
    sub2_auth = None
    code_verifier = None
    code_challenge = None
    auth_url = None
    if auth_source == "cpa":
        cpa_auth = codex_oauth._request_cpa_authorize_url()
        state = cpa_auth["state"]
        auth_url = cpa_auth["auth_url"]
    elif auth_source == "sub2":
        sub2_auth = codex_oauth._request_sub2_authorize_url()
        state = sub2_auth["state"]
        auth_url = sub2_auth["auth_url"]
    elif auth_source == "local":
        code_verifier, code_challenge = codex_oauth._generate_pkce()
        state = codex_oauth._generate_state()
        auth_url = codex_oauth._build_authorize_url(state, code_challenge, prompt="login")
    else:
        raise RuntimeError(f"[Codex] 不支持的 CODEX_AUTH_URL_SOURCE={auth_source!r}")

    auth_url = codex_oauth._ensure_oai_context_url(auth_url, session)
    # Start every account from a clean browser so a continuous pipeline never
    # carries the previous account's cookies/session/consent into the next
    # (root cause of /choose-an-account and "consent verifier already used").
    logger.info("[Codex] 账号开始前清理浏览器（Cookies/会话/缓存/存储），保持隐私模式")
    _bridge_cleanup()
    _bridge_navigate("https://chatgpt.com/login")
    _bridge_navigate("https://auth.openai.com/log-in")
    _bridge_navigate(auth_url)
    time.sleep(1.0)

    email_result = _bridge_page_action("submit_email", email=email)
    email_stage = str(email_result.get("next_stage") or "").strip().lower()

    if password_totp_login:
        if not password or not callable(totp_provider):
            raise ValueError("密码 + TOTP 账号缺少密码或 TOTP 提供器")
        password_result = _bridge_page_action("submit_password", password=password)
        if str(password_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] 密码验证失败：{str(password_result.get('error_text') or '')[:240]}")
        time.sleep(0.5)
        mfa_result = _bridge_page_action("submit_mfa_totp", code=str(totp_provider() or "").strip())
        if str(mfa_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] TOTP 2FA 验证失败：{str(mfa_result.get('error_text') or '')[:240]}")
    else:
        otp_after_ts = time.time()
        if email_stage == "create-account-password":
            # New flow: the page landed on create-account/password and NO OTP has
            # been sent yet. Trigger the one-time-code registration first so the
            # OTP email actually goes out, then wait for it — never poll the
            # mailbox while still sitting on the password page.
            logger.info("[Codex] 提交邮箱后直接进入设置密码页，先触发一次性验证码注册再等待邮箱 OTP")
            otp_after_ts, advanced_stage = _advance_past_create_account_password(
                settings, email, signup_password, logger
            )
            if advanced_stage and advanced_stage != "otp":
                raise RuntimeError(
                    f"[Codex] 设置密码页处理后未进入邮箱验证码页面（当前阶段：{advanced_stage or 'unknown'}）"
                )
        email_otp = _wait_for_email_otp(
            logger,
            otp_provider,
            email,
            after_ts=otp_after_ts,
            settings=settings,
        )
        logger.info("[Codex] 邮箱 OTP 已收到")
        email_otp_result = _bridge_page_action(
            "submit_email_otp",
            code=email_otp,
        )
        if str(email_otp_result.get("error_text") or "").strip():
            raise RuntimeError(f"[Codex] 邮箱 OTP 验证失败：{str(email_otp_result.get('error_text') or '')[:240]}")
        next_stage = str(email_otp_result.get("next_stage") or "").strip().lower()
        if next_stage == "create-account-password":
            logger.info("[Codex] 邮箱 OTP 后进入设置密码页，先尝试 CDP 可信点击“一次性验证码注册”")
            passwordless_otp_after_ts = time.time()
            passwordless_result = _bridge_page_action("activate_passwordless_signup")
            if str(passwordless_result.get("error_text") or "").strip():
                raise RuntimeError(
                    f"[Codex] 一次性验证码注册切换失败：{str(passwordless_result.get('error_text') or '')[:240]}"
                )
            passwordless_stage = str(
                passwordless_result.get("next_stage")
                or passwordless_result.get("stage")
                or ""
            ).strip().lower()
            if passwordless_result.get("passwordless_disabled"):
                logger.info("[Codex] 当前环境禁用无密码注册，改为自动设置密码继续")
                _persist_signup_password(settings, email, signup_password)
                secondary_otp_after_ts = time.time()
                signup_password_result = _bridge_page_action(
                    "submit_signup_password",
                    password=signup_password,
                )
                if signup_password_result.get("used_signup_password"):
                    logger.info("[Codex] 已自动提交注册密码继续")
                if str(signup_password_result.get("error_text") or "").strip():
                    raise RuntimeError(
                        f"[Codex] 自动设置密码后继续失败：{str(signup_password_result.get('error_text') or '')[:240]}"
                    )
                signup_password_stage = str(signup_password_result.get("next_stage") or "").strip().lower()
                if signup_password_stage == "otp":
                    logger.info("[Codex] 自动设置密码后进入邮箱验证页，继续等待第二封邮箱 OTP")
                    secondary_email_otp = _wait_for_email_otp(
                        logger,
                        otp_provider,
                        email,
                        after_ts=secondary_otp_after_ts,
                        settings=settings,
                    )
                    logger.info("[Codex] 第二封邮箱 OTP 已收到")
                    secondary_email_otp_result = _bridge_page_action(
                        "submit_email_otp",
                        code=secondary_email_otp,
                    )
                    if str(secondary_email_otp_result.get("error_text") or "").strip():
                        raise RuntimeError(
                            f"[Codex] 第二封邮箱 OTP 验证失败：{str(secondary_email_otp_result.get('error_text') or '')[:240]}"
                        )
            else:
                if passwordless_stage:
                    logger.info("[Codex] CDP 可信点击一次性验证码注册后进入阶段：%s", passwordless_stage)
                if passwordless_stage == "otp":
                    logger.info("[Codex] 已切到邮箱验证码注册，继续等待第二封邮箱 OTP")
                    secondary_email_otp = _wait_for_email_otp(
                        logger,
                        otp_provider,
                        email,
                        after_ts=passwordless_otp_after_ts,
                        settings=settings,
                    )
                    logger.info("[Codex] 第二封邮箱 OTP 已收到")
                    secondary_email_otp_result = _bridge_page_action(
                        "submit_email_otp",
                        code=secondary_email_otp,
                    )
                    if str(secondary_email_otp_result.get("error_text") or "").strip():
                        raise RuntimeError(
                            f"[Codex] 第二封邮箱 OTP 验证失败：{str(secondary_email_otp_result.get('error_text') or '')[:240]}"
                        )
                    secondary_stage = str(
                        secondary_email_otp_result.get("next_stage") or ""
                    ).strip().lower()
                    if secondary_stage:
                        logger.info("[Codex] 第二封邮箱 OTP 提交后进入阶段：%s", secondary_stage)
                    if secondary_stage not in {"phone", "callback", "post-otp", ""}:
                        raise RuntimeError(f"[Codex] 第二封邮箱 OTP 后进入未处理阶段：{secondary_stage}")
                elif passwordless_stage and passwordless_stage not in {"phone", "callback", "post-otp"}:
                    raise RuntimeError(f"[Codex] 一次性验证码注册切换后进入未处理阶段：{passwordless_stage}")

    # Only acquire an SMS number when OpenAI actually presents the phone step.
    # An already phone-verified account re-running login/OAuth goes straight to
    # the consent/authorize page or the callback URL — running the接码 loop
    # there just wastes numbers and dies on "未找到手机号输入框".
    probe = _bridge_page_action("probe_stage", timeout=40.0, timeout_ms=20000, raise_on_error=False)
    probe_stage = str(probe.get("stage") or "").strip().lower()
    needs_phone = bool(probe.get("has_phone_input")) or probe_stage == "phone"
    if not needs_phone:
        logger.info(
            "[Codex] 官方流程未进入手机验证页（阶段=%s），该账号无需接码，直接收尾",
            probe_stage or "未知",
        )
    else:
        http = codex_oauth.sms_provider._http()
        try:
            # No fixed换号次数: try every channel × country combination once
            # (the cursor rotates to a fresh country each acquisition), then fail.
            max_retries = _sms_slot_count()
            provider = codex_oauth._sms_provider_name()
            last_err = None
            for attempt in range(1, max_retries + 1):
                activation_id = None
                try:
                    # After the first attempt OpenAI pins the previously submitted
                    # number on the /phone-verification CODE step. The number-ENTRY
                    # form lives at a DIFFERENT url — https://auth.openai.com/add-phone
                    # — so open it before spending a fresh SMS number; otherwise
                    # submit_phone lands on the stale code page and wastes the number.
                    if attempt > 1:
                        try:
                            _bridge_navigate("https://auth.openai.com/add-phone")
                        except RuntimeError as nav_exc:
                            logger.warning("[Codex] 打开手机号输入页(/add-phone)失败：%s", nav_exc)
                    activation_id, phone = codex_oauth.sms_provider.acquire_number(http)
                    active_channel = provider
                    route_for = getattr(codex_oauth.sms_provider, "route_for", None)
                    if callable(route_for):
                        route = route_for(activation_id)
                        channel = getattr(route, "channel", None) if route is not None else None
                        if channel:
                            active_channel = str(channel)
                    logger.info(
                        f"[Codex] 手机验证尝试 {attempt}/{max_retries}，"
                        f"provider={active_channel}, activation_id={activation_id}, 号码=+{phone}"
                    )
                    submit_result = _bridge_page_action(
                        "submit_phone", phone_number=f"+{phone}", raise_on_error=False
                    )
                    if submit_result.get("needs_phone_page"):
                        # A prior attempt left the browser on the code-entry page and
                        # there was no in-page way back to phone entry. Re-navigate to
                        # a fresh phone-verification page, drop this number, and retry.
                        stuck_state = submit_result.get("state") or {}
                        stuck_url = str(stuck_state.get("url") or "").strip()
                        stuck_snapshot = submit_result.get("snapshot") or {}
                        stuck_text = str(stuck_snapshot.get("body_text") or "").strip()
                        logger.warning(
                            "[Codex] 页面停留在验证码输入步骤（未找到手机号输入框），"
                            "重新打开手机号输入页后换号重试；当前页面=%s",
                            stuck_url or "未知",
                        )
                        if stuck_text:
                            logger.warning("[Codex] 卡住页面文本片段：%s", stuck_text[:400])
                        if "/email-verification" in stuck_url.lower():
                            # Not a phone page at all — the code inputs submit_phone
                            # tripped over are the EMAIL OTP fields, meaning the email
                            # OTP was rejected (wrong/expired code) and the flow never
                            # legitimately reached phone entry. Re-navigating to
                            # /phone-verification only shows a number-less code page and
                            # burns SMS numbers in a loop, so fail fast with the cause.
                            codex_oauth.sms_provider.cancel(activation_id, http)
                            raise RuntimeError(
                                "[Codex] 邮箱验证码未通过：页面仍停留在 email-verification（通常是取码接口"
                                "返回了错误/过期的验证码），已停止后续接码，请检查取码来源"
                            )
                        try:
                            _bridge_navigate("https://auth.openai.com/add-phone")
                        except RuntimeError as nav_exc:
                            logger.warning(f"[Codex] 重新打开手机号输入页(/add-phone)失败：{nav_exc}")
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        # Confirm the number-entry form actually came back. If the
                        # page is still stuck on the code step, acquiring more numbers
                        # would just waste them one per second — stop with a clear cause.
                        recheck = _bridge_page_action(
                            "probe_stage", timeout=40.0, timeout_ms=20000, raise_on_error=False
                        )
                        if not recheck.get("has_phone_input"):
                            raise RuntimeError(
                                "[Codex] 无法回到手机号输入页(/add-phone)，页面仍停留在上一个号码的验证码步骤，"
                                "已停止接码以免继续浪费短信号码"
                            )
                        codex_oauth._sleep_before_phone_retry(attempt, max_retries)
                        continue
                    if submit_result.get("ok") is False:
                        # Any other structured failure: cancel the acquired number
                        # (setStatus=8, avoids being charged for a later stray SMS)
                        # then surface it as a provider-style error.
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        raise RuntimeError(
                            str(submit_result.get("error") or submit_result.get("error_text") or "提交手机号失败")
                        )
                    channel_error = str(submit_result.get("channel_error") or "").strip().lower()
                    error_text = str(submit_result.get("error_text") or "")
                    if channel_error == "whatsapp":
                        # Requirement 2: the page selected WhatsApp delivery (or only
                        # offers it), which Hero/smsbower cannot receive. Drop this
                        # number and advance to the next channel/country priority.
                        logger.warning(
                            f"[Codex] 号码 +{phone} 的国家/渠道走 WhatsApp 验证，短信无法接收，"
                            f"切换下一优先级重试：{error_text[:160]}"
                        )
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        codex_oauth._sleep_before_phone_retry(attempt, max_retries)
                        continue
                    if channel_error == "other" or error_text:
                        # Requirement 3: any other red error is treated as the phone
                        # number being unusable/occupied — re-acquire a new number
                        # without inspecting the message text.
                        logger.warning(
                            f"[Codex] 号码 +{phone} 被判定为占用/不可用，重新取号重试：{error_text[:200]}"
                        )
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        codex_oauth._sleep_before_phone_retry(attempt, max_retries)
                        continue
                    codex_oauth.sms_provider.set_status(activation_id, 1, http=http)
                    code_wait = _channel_code_wait(active_channel, codex_oauth._cfg.SMS_CODE_WAIT)
                    try:
                        logger.info(
                            f"[Codex] 短信已发送，开始轮询验证码 activation_id={activation_id}, "
                            f"channel={active_channel}, wait={code_wait}s, interval={codex_oauth._cfg.SMS_POLL_INTERVAL}s"
                        )
                        sms_code = codex_oauth.sms_provider.wait_for_sms_code(
                            activation_id, http, code_wait
                        )
                    except codex_oauth.sms_provider.SmsCodeTimeout:
                        logger.warning(f"[Codex] 号码 +{phone} 在 {code_wait}s 内未收到短信，取消换号")
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        codex_oauth._sleep_before_phone_retry(attempt, max_retries)
                        continue
                    validate_result = _bridge_page_action("submit_phone_otp", code=sms_code)
                    validate_error = str(validate_result.get("error_text") or "")
                    if validate_error:
                        logger.warning(f"[Codex] phone-otp/validate 页面提示异常：{validate_error[:240]}，换号重试")
                        codex_oauth.sms_provider.cancel(activation_id, http)
                        codex_oauth._sleep_before_phone_retry(attempt, max_retries)
                        continue
                    codex_oauth.sms_provider.complete(activation_id, http)
                    logger.info("[Codex] 手机号验证通过")
                    break
                except codex_oauth.sms_provider.SmsNoBalanceError:
                    raise
                except codex_oauth.sms_provider.SmsProviderError as exc:
                    last_err = exc
                    if activation_id:
                        codex_oauth.sms_provider.cancel(activation_id, http)
                    # Nothing available on any channel/country right now — no point
                    # burning the remaining attempts, they'd all hit the same wall.
                    no_numbers = getattr(codex_oauth.sms_provider, "SmsNoNumbersError", None)
                    if no_numbers is not None and isinstance(exc, no_numbers):
                        logger.warning(f"[Codex] 所有渠道/国家当前均无可用号码，停止接码：{exc}")
                        break
                    logger.warning(f"[Codex] 接码尝试 {attempt} 失败：{exc}")
                    codex_oauth._sleep_before_phone_retry(attempt, max_retries)
            else:
                raise RuntimeError(
                    f"[Codex] 已尝试全部 {max_retries} 个渠道×国家组合仍未通过手机验证"
                    f"（provider={provider}）"
                    + (f"，最后错误：{last_err}" if last_err else "")
                )
        finally:
            http.close()

    about_you_name, about_you_age = _generate_about_you_profile()
    logger.info("[Codex] 进入收尾流程（如遇 /about-you 将自动填写 姓名=%s 年龄=%s）", about_you_name, about_you_age)
    finalize = _bridge_page_action(
        "finalize_and_get_callback",
        timeout=180.0,
        timeout_ms=120000,
        full_name=about_you_name,
        age=about_you_age,
    )
    callback_url = str(finalize.get("callback_url") or "")
    if not callback_url:
        state_info = finalize.get("state") if isinstance(finalize.get("state"), dict) else {}
        callback_url = str(state_info.get("url") or "")
    code = codex_oauth._extract_code(callback_url, state)
    logger.info(f"[Codex] 已拿到 authorization code：{code[:24]}...")

    if auth_source == "cpa":
        submit_payload = codex_oauth._submit_cpa_callback(callback_url)
        path = codex_oauth._save_cpa_local_record(
            email=email,
            callback_url=callback_url,
            auth_url=auth_url or "",
            state=state,
            submit_payload=submit_payload,
        )
        msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
        return codex_oauth._codex_result(
            status="success",
            ok=True,
            email=email,
            file_path=str(path) if path else None,
            callback_url=callback_url,
            message=str(msg),
        )

    if auth_source == "sub2":
        submit_payload = codex_oauth._submit_sub2_callback(
            callback_url,
            session_id=(sub2_auth or {}).get("session_id", ""),
            redirect_uri=(codex_oauth.parse_qs(codex_oauth.urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
        )
        path = codex_oauth._save_sub2_local_record(
            email=email,
            callback_url=callback_url,
            auth_url=auth_url or "",
            state=state,
            submit_payload=submit_payload,
        )
        msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
        return codex_oauth._codex_result(
            status="success",
            ok=True,
            email=email,
            file_path=str(path) if path else None,
            callback_url=callback_url,
            message=str(msg),
        )

    if not code_verifier:
        raise RuntimeError("[Codex] local 模式缺少 code_verifier")
    token_resp = codex_oauth.exchange_codex_token(session, code, code_verifier)
    id_claims = codex_oauth._parse_id_token(token_resp.get("id_token", ""))
    effective_email = id_claims.get("email") or email
    storage = codex_oauth.build_codex_storage(token_resp, id_claims)
    path = codex_oauth.save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))
    return codex_oauth._codex_result(
        status="success",
        ok=True,
        email=effective_email,
        file_path=str(path),
        callback_url=callback_url,
        message=f"plan={id_claims.get('plan_type') or 'unknown'}",
    )


def run_codex_only(settings: Settings, mailbox: dict, *, cancel_event=None) -> dict:
    """Run only the upstream existing-account Codex OAuth entrypoint.

    ``cancel_event`` (a threading.Event) lets the scheduler ask a running job to
    bail out of long cooperative waits (currently the gcash 扫码 wait) promptly,
    since a worker thread cannot be force-killed.
    """

    email = str(mailbox.get("email") or "").strip()
    if not email:
        raise ValueError("邮箱为空")
    # When the job was dispatched in "session export" mode, capture and save
    # chatgpt.com/api/auth/session after a successful login (browser mode only).
    capture_session = bool(mailbox.get("export_session"))
    # "仅登录" mode: sign the account into chatgpt.com and stop there.
    login_only = bool(mailbox.get("login_only"))
    # "gcash 提炼" mode: login → accessToken → 153 提炼 → 付款链接 → 等待扫码.
    gcash_extract = bool(mailbox.get("gcash_extract"))
    source = str(mailbox.get("source") or "").strip().lower()
    codex_oauth = _ensure_upstream_imports(settings)

    password = ""
    totp_provider = None
    if source == "outlook":
        otp_provider, cleanup = _outlook_otp_provider(mailbox)
    elif source in {"generic_api", "code_url"}:
        otp_provider, cleanup = _generic_api_otp_provider(mailbox)
    elif source == "password_totp":
        password = str(mailbox.get("password") or "")
        totp_secret = str(mailbox.get("totp_secret") or "")
        if not password or not totp_secret:
            raise ValueError("密码 + 2FA 账号缺少密码或 TOTP 密钥")
        otp_provider = None
        totp_provider = lambda: current_totp(totp_secret)
        cleanup = lambda: None
    else:
        raise ValueError(f"暂不支持的邮箱来源: {source}")

    sms_provider = getattr(codex_oauth, "sms_provider", None)
    hero_patch = None
    try:
        if sms_provider is None:
            raise RuntimeError("原项目未提供短信生命周期模块，无法启用 Hero SMS")
        hero_patch = install_hero_sms_patch(sms_provider)
        if hero_patch is None:
            raise RuntimeError("Hero SMS 适配器安装失败，已阻止使用其他接码平台")
        if _browser_flow_available():
            if gcash_extract:
                logging.getLogger(__name__).info("[Codex] 浏览器桥已连接，进入 gcash 提炼模式（两个绑定标签页，不接码/不 OAuth）")
                try:
                    return _run_gcash_extraction(
                        settings,
                        mailbox,
                        otp_provider=otp_provider,
                        password=password,
                        totp_provider=totp_provider,
                        cancel_event=cancel_event,
                    )
                except RuntimeError as exc:
                    message = str(exc)
                    # A closed / re-bound tab cannot be fixed by rerunning the
                    # same account, so make sure it lands as non-retryable
                    # instead of matching the generic "超时" retry rule.
                    if _GCASH_FAILED_TOKEN in message or "标签页" not in message:
                        raise
                    raise RuntimeError(f"[Codex] {_GCASH_FAILED_TOKEN}：{message}") from exc
            if login_only:
                logging.getLogger(__name__).info("[Codex] 浏览器桥已连接，进入仅登录模式（不导出 Session/不接码/不 OAuth）")
                return _run_login_only(
                    settings,
                    mailbox,
                    otp_provider=otp_provider,
                    password=password,
                    totp_provider=totp_provider,
                )
            if capture_session:
                logging.getLogger(__name__).info("[Codex] 浏览器桥已连接，进入 Session 导出模式（仅登录，不接码/不 OAuth）")
                return _run_session_export(
                    settings,
                    mailbox,
                    otp_provider=otp_provider,
                    password=password,
                    totp_provider=totp_provider,
                )
            logging.getLogger(__name__).info("[Codex] 浏览器桥已连接，切换到当前活动页浏览器模式")
            return _run_codex_in_browser(
                settings,
                mailbox,
                otp_provider=otp_provider,
                password=password,
                totp_provider=totp_provider,
            )
        if capture_session:
            raise RuntimeError("[Codex] Session 导出需要浏览器桥（活动页带 cookie 读取 session），当前未连接")
        if gcash_extract:
            raise RuntimeError(f"[Codex] {_GCASH_FAILED_TOKEN}：gcash 提炼需要浏览器桥（要操作两个绑定标签页），当前未连接")
        if login_only:
            raise RuntimeError("[Codex] 仅登录需要浏览器桥（在当前活动页完成登录），当前未连接")
        logging.getLogger(__name__).warning("[Codex] 浏览器桥未连接，回退到 Python 后端会话模式")
        # 这是原项目的 Codex 补跑入口；不导入也不调用 main.run_registration。
        kwargs = {
            "otp_provider": otp_provider,
            "proxy": None,
            "force": True,
        }
        if source == "password_totp":
            kwargs.update(password=password, totp_provider=totp_provider)
        result = codex_oauth.run_codex_oauth(email, **kwargs)
    finally:
        try:
            if hero_patch is not None:
                hero_patch.restore()
        finally:
            cleanup()

    if not isinstance(result, dict):
        raise RuntimeError("原项目 Codex OAuth 未返回结构化结果")
    return result
