from __future__ import annotations

import base64
import binascii
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
from .notice_store import notices
from .settings import Settings
from .totp_auth import current_totp, normalize_totp_secret
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
# Browser-side waiting budgets, configured in 插件「调试」页 → 通用配置. Resolved
# lazily because Settings is not available at import time here.
_browser_config_store = None


def _browser_config() -> dict:
    global _browser_config_store
    if _browser_config_store is None:
        try:
            from .browser_config_store import BrowserConfigStore
            from .settings import load_settings

            _browser_config_store = BrowserConfigStore(load_settings().data_dir)
        except Exception:  # pragma: no cover - defensive: fall back to defaults
            return {"page_load_timeout_ms": 45_000, "element_wait_timeout_ms": 30_000}
    return _browser_config_store.get()


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
    # Hand the browser its own waiting budget so a slow network (or a proxy in
    # the middle) can be accommodated from the UI instead of by editing JS.
    if kind in {"navigate", "reload"} and "page_load_timeout_ms" not in payload:
        payload = {**payload, "page_load_timeout_ms": _browser_config()["page_load_timeout_ms"]}
    elif kind == "page_action" and "element_wait_timeout_ms" not in payload:
        payload = {**payload, "element_wait_timeout_ms": _browser_config()["element_wait_timeout_ms"]}
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


def _bridge_navigate(
    url: str,
    *,
    timeout: float | None = None,
    retries: int = 2,
    ready_selector: str = "",
    tolerate_timeout: bool = False,
) -> dict:
    # A navigate that times out never completed, so re-issuing the same GET is
    # safe. Chrome MV3 service workers go idle and can miss the first request,
    # and the cold Cloudflare challenge on the first chatgpt.com/login load (esp.
    # right after a full cookie wipe) can exceed the tab-load window; a couple of
    # retries let a transient stall self-recover instead of killing the job.
    #
    # ``tolerate_timeout`` is for pages that may never report "load complete" at
    # all — chatgpt.com holds connections open, so through a proxy the tab can
    # sit in 'loading' indefinitely while the UI is perfectly usable. There the
    # timeout says nothing about whether we can proceed, and the next step
    # (which waits for its own controls) is the real arbiter.
    if timeout is None:
        from .browser_config_store import navigate_bridge_timeout_ms

        # Always longer than the browser's own page-load budget — if both sides
        # expired together the job would be orphaned (CLAUDE.md 踩坑 #2).
        timeout = navigate_bridge_timeout_ms(_browser_config()) / 1000.0
    last_exc: RuntimeError | None = None
    payload = {"url": url}
    if ready_selector:
        payload["ready_selector"] = ready_selector
    for attempt in range(retries + 1):
        try:
            return _bridge_request("navigate", payload, timeout=timeout)
        except RuntimeError as exc:
            if "超时" not in str(exc):
                raise
            if tolerate_timeout:
                logging.getLogger(__name__).warning(
                    "[Codex] 页面未报告加载完成（%s），但继续按页面控件推进：%s", url, exc
                )
                return {"ok": True, "url": url, "load_timeout": True}
            if attempt >= retries:
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


def _bridge_reload(*, timeout: float | None = None, ready_selector: str = "") -> dict:
    """Reload the current tab (the scripted equivalent of pressing F5).

    Needed when a page loaded fine but did not do what it was supposed to, so
    re-injecting into it is pointless: the second request carries the cookies
    the first response set.
    """
    if timeout is None:
        from .browser_config_store import navigate_bridge_timeout_ms

        timeout = navigate_bridge_timeout_ms(_browser_config()) / 1000.0
    payload: dict = {}
    if ready_selector:
        payload["ready_selector"] = ready_selector
    return _bridge_request("reload", payload, timeout=timeout)


def _bridge_page_action(action: str, **payload) -> dict:
    from .browser_config_store import page_action_bridge_timeout_ms

    # Default derived from the configured element-wait budget so raising that in
    # the UI never makes the browser outlive this request (orphaned job).
    default_timeout = page_action_bridge_timeout_ms(_browser_config()) / 1000.0
    timeout = float(payload.pop("timeout", default_timeout))
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
    # 清理是否真的生效，靠回执说话而不是假设：残留 cookie 正是 OpenAI 弹
    # /choose-an-account（"Welcome back，上一个账号还在"）的直接原因。
    remaining = int(result.get("remaining_cookies") or 0)
    if remaining:
        logger.warning(
            "[Codex] 浏览器清理后仍残留 %d 个 cookie：%s（下一步很可能弹 /choose-an-account）",
            remaining,
            ", ".join(str(item) for item in (result.get("remaining_cookie_names") or []))[:300],
        )
    else:
        logger.info(
            "[Codex] 浏览器清理完成：cookie 已清空，顺带停用 %s 个仍停在目标站点的标签页",
            result.get("parked_tabs") or 0,
        )
    return result


def _bridge_apply_proxy(mailbox: dict, *, label: str = "任务") -> None:
    """Point the browser at this account's proxy before it loads anything.

    ``mailbox['proxy']`` is filled by the scheduler's round-robin over the pool;
    absent means "no proxy for this account", which still has to be sent so the
    browser drops a proxy left over from the previous account. Failure is logged
    but never fatal — losing the proxy must not kill an otherwise fine job.
    """
    logger = logging.getLogger(__name__)
    proxy = mailbox.get("proxy") if isinstance(mailbox.get("proxy"), dict) else None
    try:
        result = _bridge_request(
            "proxy_apply", {"proxy": proxy}, timeout=30.0, raise_on_error=False
        )
    except RuntimeError as exc:
        logger.warning("[Codex] %s：设置浏览器代理失败：%s", label, exc)
        return
    if not result.get("ok"):
        logger.warning("[Codex] %s：设置浏览器代理返回失败：%s", label, result.get("error") or "")
        return
    if proxy:
        logger.info(
            "[Codex] %s：浏览器代理已切换到 %s（%s://%s:%s）",
            label,
            proxy.get("label") or proxy.get("id") or "",
            proxy.get("scheme"),
            proxy.get("host"),
            proxy.get("port"),
        )
        # The timezone/language the browser reports is no longer derived from
        # this proxy — it is whatever the operator pinned in 调试 → 指纹. Log it
        # next to the proxy anyway: a clock that contradicts the exit IP is a
        # stronger "proxy" tell than the IP itself.
        if result.get("fingerprint_enabled"):
            logger.info(
                "[Codex] %s：浏览器指纹（用户指定）：时区 %s · 语言 %s",
                label,
                result.get("fingerprint_timezone") or "",
                result.get("fingerprint_language") or "",
            )
        else:
            logger.warning(
                "[Codex] %s：未启用指纹覆盖，浏览器仍报本机时区/语言（代理测出的时区为 %s），风控可能据此识别代理",
                label,
                result.get("proxy_timezone") or "未知",
            )
        if result.get("warning"):
            logger.warning("[Codex] %s：%s", label, result.get("warning"))
    else:
        logger.info("[Codex] %s：未分配代理，浏览器已恢复直连", label)


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
    endpoint instead of treating it as a failure.

    A ``浏览器桥接超时`` on the submit is treated the same way: the login often
    DID succeed (page jumped to chatgpt.com, the injected frame died in a
    throttled background tab, and the bridge hit its 120s cap before the step
    could report back). Failing outright here would throw away a good login;
    instead defer to ``_confirm_logged_in``, which reads the session endpoint and
    is the single source of truth. If the login really didn't happen it just
    fails there after genuinely checking, so this never fabricates success.

    "可信点击落空"（目标被瞬时遮挡 / 元素刚挪走）同样不是失败：那一下点击**根本
    没派发出去**（SW 派发前会重新量坐标并确认目标就在那个点上），所以整步重跑不会
    重复提交，只是等页面稳定再来一次。"""
    try:
        return _page_action_with_click_retry(action, logger, label=label, step=step, **payload)
    except RuntimeError as exc:
        teardown = _is_frame_teardown_error(exc)
        bridge_timeout = "浏览器桥接超时" in str(exc)
        if not teardown and not bridge_timeout:
            raise
        if bridge_timeout and not teardown:
            logger.warning(
                "[Codex] %s：%s 桥接超时（可能页面已跳转、注入帧在后台被节流未回信），改用 session 接口确认结果：%s",
                label,
                step,
                str(exc)[:160],
            )
        else:
            logger.info(
                "[Codex] %s：%s 后注入帧被销毁（页面正在跳转），改用 session 接口确认结果：%s",
                label,
                step,
                str(exc)[:160],
            )
        return {"ok": True, "frame_teardown": True, "error_text": "", "teardown_error": str(exc)}


_LOGIN_WITH_URL = "https://chatgpt.com/auth/login_with?callback_path=/"
# The extension raises this token when chatgpt.com served the logged-out SPA
# shell instead of redirecting to auth.openai.com.
_LOGIN_WITH_SHELL_TOKEN = "login_with_shell"
# The login page sometimes defaults to the phone-number form, which has no email
# box at all — the flow then waits out its whole budget and fails on "未找到邮箱
# 输入框". ?usernameKind=email pins it to email entry.
_OPENAI_LOGIN_URL = "https://auth.openai.com/log-in?usernameKind=email"
# Entry points to the email form, tried in order.
#   1. auth.openai.com/log-in — the login page itself, and by far the lightest.
#      After a cookie wipe it may be the "会话已结束" interstitial whose only
#      control is a 登录 link, but submit_email just clicks that.
#   2. chatgpt.com root — its 登录 button reaches the same place.
#   3. chatgpt.com/auth/login_with — the old primary. Kept only as a last
#      resort: it is a heavy SPA route that fairly often renders the logged-out
#      chat landing page instead of redirecting, which wastes a whole attempt.
# Each entry is a *different HTTP request*, which is the only thing that can fix
# a page that loaded fine but refused to redirect. Retrying the same URL cannot.
_LOGIN_ENTRY_URLS = (
    _OPENAI_LOGIN_URL,
    "https://chatgpt.com/",
    _LOGIN_WITH_URL,
)
# With a proxy in play, only chatgpt.com works: the auth.openai.com entries end
# up bounced back to "你的会话已结束", and everything funnels through this page
# anyway. Trying the others first just burns a full attempt each.
# The route from here is: click the top-right "Log in" → the "Log in or sign up"
# dialog opens on PHONE entry → click "Continue with email" → email box.
_PROXY_LOGIN_ENTRY_URLS = ("https://chatgpt.com/",)
# 注册入口 —— 和登录入口是两回事，绝不能混用。
# /log-in 是**登录**页：往里填一个全新地址，OpenAI 会回「Enter your password」
# （/log-in/password），流程直接死在那里，还很容易被误读成"这个号已经注册过了"。
# 注册必须走 /create-account，它才会给出 /email-verification 验证码页，
# 再由「Continue with password」进 /create-account/password 设密码。
_SIGNUP_ENTRY_URLS = (
    "https://chatgpt.com/",
    "https://auth.openai.com/create-account",
)
# **为什么首页排在 /create-account 前面（2026-08-12 直连实测）**：
# logs/codex-7c4f2e28fe801a14090542d3-5bf08f2d-a1.log、codex-457624dc85202443bf8e3568：
# 无代理、清完 cookie 后 GET /create-account，**连续 5 轮全是 `Your session has ended`**
# （`is_missing_session:true`，整页只有一个 Log in 链接、没有任何输入框），每轮都先经
# chatgpt.com 重新种会话，**一次都没生效**；换 `chatgpt.com/auth/login_with?screen_hint=
# signup` 又被重定向回同一张中转页，再废 5 轮，整单失败还白烧一个取号。
# 同一批日志里代理跑的 codex-0c253ac577af3bc3447052b9 从 chatgpt.com 首页进弹窗，
# 一路 otp → 设密码 → about-you 注册成功。所以"预热能把 /create-account 的会话种起来"
# 这个前提已经不成立了，直连和代理一样只能从首页进；/create-account 只留作后备
# （会话真的建起来时它是直达的，登录页上的 Sign up 链接 href 就是它）。
# `?screen_hint=signup` 那个入口已删除：它落到的就是同一张中转页，纯属白等。
# **代理模式下的注册入口**：只走 chatgpt.com 首页，点右上角「Log in」进那个
# 「Log in or sign up」弹窗 →「Continue with email」→ 输邮箱，后面照旧。
# 代理下**连后备都不给** auth.openai.com/create-account：
# 依据（logs/codex-a87e3d33c1101746f29f9537-6782ed72-a1.log，jp 住宅代理）：
# `auth.openai.com/create-account` 连续 5 轮全部渲染成 `Your session has ended`
# （每轮都先经 chatgpt.com 重新种会话，无效）；第 6 轮好不容易过去，提交邮箱直接
# 落 `login-password`，点「Sign up」回到 create-account 再提交还是 `login-password`，
# 第三次变 `unknown` 收工。也就是说走代理时 auth.openai.com 这个入口拿不到注册表单，
# 再怎么重发都是白烧一个取号。chatgpt.com 那个弹窗本身就叫 **"Log in or sign up"**，
# 是同一套 identifier-first 流程，新地址会走到 /email-verification。
# 注意：这跟"注册入口和登录入口不能混用"（上面 _SIGNUP_ENTRY_URLS 的告诫）不冲突——
# 被禁的是 `auth.openai.com/log-in` 那个**纯登录**页，以及"会话已结束"中转页上那条
# 把注册拖进登录的 Log in 链接；chatgpt.com 首页的 Log in 按钮进的是二合一弹窗。
_PROXY_SIGNUP_ENTRY_URLS = ("https://chatgpt.com/",)
# 入口是 chatgpt.com 首页时，页面上一开始**没有任何输入框**（要先点 Log in 才有），
# 所以就绪判据、预热、以及"会话中转页"的恢复方式都要按登录那套来，不能按注册那套。
_CHATGPT_HOME_RE = re.compile(r"^https?://(www\.)?chatgpt\.com/?(\?.*)?$", re.I)
# 非首页的注册入口落在"会话已结束"中转页时，最多重新种几次会话就换下一个入口。
# 实测种会话对 /create-account 已经完全无效（见 _SIGNUP_ENTRY_URLS 的日志），
# 原来的 6 轮 × 两个入口 = 白等 90s 才失败；留 2 轮只是给偶发情况一个机会。
_SIGNUP_RESEED_ROUNDS = 2


def _signup_entry_urls(mailbox: dict) -> tuple[str, ...]:
    """注册入口阶梯：一律先走 chatgpt.com 首页，代理下只走它。"""

    if isinstance(mailbox.get("proxy"), dict):
        return _PROXY_SIGNUP_ENTRY_URLS
    return _SIGNUP_ENTRY_URLS


# 注册导航的"就绪"判据只认**真正的输入框**，绝不认登录链接。
# _LOGIN_READY_SELECTOR 里有 `a[href*="/log-in"]`，而"会话已结束"中转页上那个
# 「Log in」链接正好匹配——导航一看到它就返回，于是每一轮都在中转页上白跑一次
# submit_email，实测要 4~5 轮才碰上真表单（每轮 3~7s）。只等输入框的话，导航会
# 一直等到表单真的画出来（或超时后由重试逻辑换一次请求）。
_SIGNUP_READY_SELECTOR = (
    'input[type="email"], input[autocomplete="username"], input[name="username"],'
    ' input[name="email"], input[id*="email" i], input[type="password"]'
)
# 预热导航的预算。它只为拿一次 HTTP 往返（种 cookie），不需要页面渲染完；
# 用完整的页面加载预算会在慢代理下白等满，实测预热+入口一共烧掉 120s。
_SIGNUP_WARMUP_TIMEOUT = 20.0
# Navigation stops waiting the moment one of these exists, instead of waiting for
# the whole page to finish loading — the email box, or any control that leads to
# it, is all the next step needs. chatgpt.com never reliably reports "complete"
# behind a proxy, so this is what keeps the flow moving.
_LOGIN_READY_SELECTOR = (
    'input[type="email"], input[autocomplete="username"], input[name="username"],'
    ' input[name="email"], input[id*="email" i], input[type="password"],'
    ' input[type="tel"],'
    ' a[href*="/auth/login_with"], a[href*="/log-in"],'
    ' [data-testid*="login" i], [data-testid*="signup" i]'
)
# The extension raises this when the page still shows a clickable 登录 control
# but no email form — i.e. we bounced back to "你的会话已结束". Re-running
# submit_email clicks it again, which is how a human gets through.
_LOGIN_RETRY_CLICK_TOKEN = "login_retry_click"
# How many times one entry may click its way forward before we try another URL.
# Each click is a fresh request that carries more session context, and the
# interstitial can legitimately appear more than once in a row.
_LOGIN_CLICK_ROUNDS = 6
# How long to let a proxied login page settle before touching it. Cloudflare's
# JS detection and OpenAI's sentinel iframe score the visit in the background;
# acting faster than they finish is what gets the session thrown away.
_PROXY_SETTLE_SECONDS = 3.0
# Errors that mean "this entry is a dead end, try the next one" rather than
# "this account/page is broken".
# 注意 `未找到邮箱输入框` 有个例外：页面可能是**已经走过邮箱这一步**才没有邮箱框，
# 那就绝不能重进入口（会把进度扔掉）。见下面 _NO_EMAIL_BOX_TOKEN 的处理。
_NO_EMAIL_BOX_TOKEN = "未找到邮箱输入框"
_LOGIN_ENTRY_DEAD_END = (_LOGIN_WITH_SHELL_TOKEN, _NO_EMAIL_BOX_TOKEN)
# 提交邮箱后被 OpenAI 直接甩去第三方身份提供商（实测 accounts.google.com）。
# 这是风控动作，不是我们点错了按钮：救不回来，也不该重试——重试只会再烧一个取号。
_RISK_BLOCK_TOKEN = "openai_risk_block"
_THIRD_PARTY_IDP_RE = re.compile(
    r"^https?://([^/]*\.)?(accounts\.google\.com|login\.microsoftonline\.com|appleid\.apple\.com"
    r"|facebook\.com|github\.com/login)",
    re.I,
)


def _risk_block_failure(url: str) -> RuntimeError:
    return RuntimeError(
        f"[Codex] {_RISK_BLOCK_TOKEN}：提交邮箱后被 OpenAI 甩到第三方登录页"
        f"（{str(url)[:120]}），这是风控拦截、救不回来，放弃该账号"
    )


def _third_party_idp_url() -> str:
    """当前标签页是不是已经被甩到第三方身份提供商了（不注入，纯读 URL）。"""

    result = _bridge_request("tab_url", {}, timeout=20.0, raise_on_error=False)
    url = str(result.get("url") or "")
    return url if _THIRD_PARTY_IDP_RE.match(url) else ""


def _wait_for_post_email_landing(logger, label: str, *, timeout: float = 25.0) -> str:
    """Watch the tab's own URL after the email was submitted.

    The in-page judgement runs inside one document and closes its window after a
    fixed budget. Through a slow proxy the navigation to /email-verification can
    land *after* that — the OTP really was sent, but the step reported "unknown"
    and the run was killed. Polling the tab URL costs nothing, needs no
    injection, and is immune to the page's language (which the locale override
    can change out from under every text-based check).
    """
    # Counted rather than wall-clock: the loop's pace IS the sleep, so counting
    # keeps it honest when sleeping is cheap (and keeps tests instant).
    interval = 1.0
    for _ in range(max(1, int(max(1.0, timeout) / interval))):
        result = _bridge_request("tab_url", {}, timeout=20.0, raise_on_error=False)
        url = str(result.get("url") or "").lower()
        # 风控甩去第三方登录页：立刻收手，别再等它变回来。
        if _THIRD_PARTY_IDP_RE.match(url):
            raise _risk_block_failure(url)
        if "/email-verification" in url:
            logger.info("[Codex] %s：页面随后跳到了 %s，验证码已发出，继续等取码", label, url[:120])
            return "otp"
        if "/create-account/password" in url:
            return "create-account-password"
        if "/phone-verification" in url or "/add-phone" in url:
            return "phone"
        time.sleep(interval)
    return ""


# 点「Continue with password」之后可能的两个落点。**必须区分**：
# /create-account/password 是注册设密码页（我们要的），/log-in/password 是登录页
# ——把自己生成的密码填进去等于拿它当已有账号的登录密码（踩坑 #17）。
_PASSWORD_PAGE_URLS = (
    ("/create-account/password", "create-account-password"),
    ("/log-in/password", "login-password"),
)
# 导航落地之后、注入下一步之前的静置窗口。URL 变了不等于页面能点了：新页面还在
# 做视图过渡时，点击会被判成"目标点被其它元素遮挡"。
_PAGE_TRANSITION_SETTLE_SECONDS = 1.2
# 扩展侧 trustedClick 报"点击落空"时用的关键词。它是瞬时状态（过渡层、回流），
# 扩展自己已经重试过；Python 侧再给一次整步重跑，别为它作废一个账号。
_CLICK_MISSED_TOKEN = "可信点击落空"
# 提交注册密码之后的落点。正常是 /email-verification（OpenAI 这时才发验证码）。
# 只列"已经往前走了"的页面：还停在 /create-account/password 就继续等，绝不能把
# "还没跳"当成落点。
_POST_SIGNUP_PASSWORD_URLS = (
    ("/email-verification", "otp"),
    ("/phone-verification", "phone"),
    ("/add-phone", "phone"),
    ("/about-you", "about-you"),
)


def _wait_for_tab_stage(
    logger, label: str, *, targets, timeout: float = 25.0, step: str = "", settle: float | None = None
) -> str:
    """轮询**标签页自身的 URL**，直到落到 ``targets`` 里的某个片段。

    只读 URL：不注入、不受页面语言影响（同踩坑 #12），也不会被"页面已经被销毁的
    那个 document"骗到。``targets`` 只列"已经往前走了"的页面，所以页面还没跳时会
    继续等，而不是把原地当落点。

    ``settle``：**URL 变了不等于页面能点了**。这些调用点后面紧跟着一次注入操作，
    而新页面此时可能还在做视图过渡（旧视图淡出层压在新视图上）、字体回流。实测
    logs/codex-2ffe475cee4fb8bb73aa7c70-1d27c48f：URL 一到 /create-account/password
    就立刻去填密码，点击被判"目标点被其它元素遮挡"，整单作废；隔 3 分钟手动重跑
    同一个账号一次就过。所以匹配到之后统一静置一小会儿再返回。
    """

    interval = 1.0
    for _ in range(max(1, int(max(1.0, timeout) / interval))):
        result = _bridge_request("tab_url", {}, timeout=20.0, raise_on_error=False)
        url = str(result.get("url") or "").lower()
        if _THIRD_PARTY_IDP_RE.match(url):
            raise _risk_block_failure(url)
        for needle, stage in targets:
            if needle in url:
                logger.info("[Codex] %s：%s页面已到 %s", label, f"{step}后" if step else "", url[:120])
                time.sleep(_PAGE_TRANSITION_SETTLE_SECONDS if settle is None else max(0.0, settle))
                return stage
        time.sleep(interval)
    return ""


def _wait_for_password_page(logger, label: str, *, timeout: float = 25.0) -> str:
    """点「Continue with password」之后，靠标签页自身的 URL 判落点。

    这一步的点击本来就会把页面带到 /create-account/password，注入帧随之销毁——
    `Frame with ID 0 was removed` 是**点成功了**的表现，不是失败。

    刻意**不复用扩展的 inspectAuthFlowStage**：它把 /log-in/password 也算成
    create-account-password，正是踩坑 #17 那个把生成密码填进登录框的误判。
    """

    return _wait_for_tab_stage(logger, label, targets=_PASSWORD_PAGE_URLS, timeout=timeout)


def _page_action_with_click_retry(action: str, logger, *, label: str, step: str, attempts: int = 3, **payload) -> dict:
    """跑一个 page_action；只在"可信点击落空"时整步重跑。

    落空 = 那一下点击**根本没派发出去**（SW 派发前重新量坐标、确认目标就在那个点上，
    不是就不点），所以重跑不会产生重复提交。它的成因都是瞬时的：新页面还在做视图
    过渡、字体回流、弹层正在收起。实测同一个账号第一遍死在这里、隔几分钟重跑一次
    就过（logs/codex-2ffe475cee4fb8bb73aa7c70-1d27c48f vs -cbd917a5）——那种"重跑就
    好"的失败不该由用户来做。
    """

    last: RuntimeError | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return _bridge_page_action(action, **payload)
        except RuntimeError as exc:
            if _CLICK_MISSED_TOKEN not in str(exc):
                raise
            last = exc
            if attempt >= attempts:
                break
            logger.warning(
                "[Codex] %s：%s时点击落空（第 %d/%d 次），等页面稳定后重试：%s",
                label,
                step,
                attempt,
                attempts,
                str(exc)[:160],
            )
            time.sleep(_PAGE_TRANSITION_SETTLE_SECONDS * attempt)
    raise last if last is not None else RuntimeError(f"[Codex] {label}：{step}失败")


def _submit_signup_password(logger, *, label: str, password: str) -> dict:
    """提交注册密码。提交成功**本来就会**跳到 /email-verification 并销毁注入帧。

    帧销毁有两种表现（踩坑 #1）：抛 `Frame with ID X was removed`，**或 executeScript
    静默返回 null → "页面动作返回空结果"**。两种 `_is_frame_teardown_error` 都认，
    但这一步以前是裸调用，没人接——于是密码明明设好了、页面已经在验证码页上，任务
    却在这里判死，连 120s 的取码都没等（实测
    logs/codex-d230681a1023b30343738ede-1e3b489f-a1.log）。
    """

    try:
        return _page_action_with_click_retry(
            "submit_signup_password", logger, label=label, step="设置账号密码", password=password
        )
    except RuntimeError as exc:
        if not _is_frame_teardown_error(exc) and "浏览器桥接超时" not in str(exc):
            raise
        logger.info(
            "[Codex] %s：提交密码后注入帧被销毁（页面正在跳转），改读标签页 URL 判落点：%s",
            label,
            str(exc)[:160],
        )
        stage = _wait_for_tab_stage(
            logger, label, targets=_POST_SIGNUP_PASSWORD_URLS, timeout=30.0, step="提交密码"
        )
        if stage:
            return {"ok": True, "next_stage": stage, "frame_teardown": True}
        raise _register_failure(
            "提交注册密码后页面发生跳转，但没有落到验证码页"
        ) from exc


# 用"已经存在的密码"登录之后的落点。填对密码后 OpenAI 会要求邮箱验证。
_POST_KNOWN_PASSWORD_URLS = (
    ("/email-verification", "otp"),
    ("/phone-verification", "phone"),
    ("/add-phone", "phone"),
    ("/about-you", "about-you"),
)


def _resume_with_known_password(logger, *, label: str, email: str, password: str) -> str:
    """重跑的账号：上一轮已经建号并设过密码，把**存下来的那个密码**填回登录页。

    OpenAI 记得这个账号的密码，所以此时的 `/log-in/password` 不是死路——填对之后它
    会要求邮箱验证（`/email-verification`），正好接回原本的取码流程。判死刑等于白扔
    一个已经建好的账号，还白烧一个取号。

    **注意这里要的正是 `/log-in/password`**：账号是我们自己建的、密码在手上，和
    "注册阶段绝不能走登录密码页"（踩坑 #17/#20）是相反的诉求——那两条针对的是
    **没有密码**的全新地址。所以这条路只在 `known_password` 非空时才走。

    返回落点阶段；`otp` 表示已经在验证码页上了。
    """

    logger.info("[Codex] %s：该地址上一轮已建号并设过密码，直接用已存密码登录", label)
    notices.push("该账号上一轮已建号，正在用已保存的密码登录…", scope="signup")
    result = _submit_login_step(
        "submit_password", label=label, step="提交已存密码", logger=logger, password=password
    )
    error = str(result.get("error_text") or "").strip()
    if error and re.search(r"incorrect email address or password|邮箱地址或密码不正确", error, re.I):
        # 密码对不上：这个地址确实已被注册，但不是被我们注册的（或密码被改过）。
        raise _account_exists_failure(email, "已存密码被 OpenAI 判为不正确")
    # 落点一律以标签页 URL 为准：不注入、不受页面语言影响，也不会被销毁的旧 document 骗到。
    stage = _wait_for_tab_stage(
        logger, label, targets=_POST_KNOWN_PASSWORD_URLS, timeout=30.0, step="提交已存密码"
    )
    if not stage:
        if error:
            raise _register_failure(f"用已存密码登录失败：{error[:200]}")
        raise _register_failure("用已存密码登录后没有落到验证码页")
    return stage


def _switch_to_password_signup(logger, *, label: str) -> str:
    """点验证码页底部的「Continue with password」，返回落点阶段。

    点击会导航，导航会销毁注入帧——所以帧销毁/桥接超时**一律不能当失败**：那样会
    把一个已经发出验证码的账号直接作废，还白烧一个取号（实测
    logs/codex-d230681a1023b30343738ede-35828900-a1.log：页面明明已经到了
    /create-account/password，却报 `Frame with ID 0 was removed.` 收工）。
    """

    try:
        switch = _page_action_with_click_retry(
            "continue_with_password", logger, label=label, step="切换到密码注册"
        )
    except RuntimeError as exc:
        if not _is_frame_teardown_error(exc) and "浏览器桥接超时" not in str(exc):
            raise
        logger.info(
            "[Codex] %s：点「Continue with password」后注入帧被销毁（页面正在跳转），改读标签页 URL 判落点：%s",
            label,
            str(exc)[:160],
        )
        stage = _wait_for_password_page(logger, label=label)
        if stage:
            return stage
        raise _register_failure(
            "点「Continue with password」后页面发生跳转，但没有落到密码设置页"
        ) from exc
    if switch.get("password_switch_missing"):
        raise _register_failure(
            "验证码页没有「Continue with password」入口，无法设置密码，放弃该账号"
        )
    if str(switch.get("error_text") or "").strip():
        raise _register_failure(f"切换密码注册失败：{str(switch.get('error_text'))[:200]}")
    stage = str(switch.get("next_stage") or "").strip().lower()
    if not stage:
        # 页内判据没认出来：慢代理下导航可能晚于判据窗口。再用 URL 兜一次。
        stage = _wait_for_password_page(logger, label=label)
    return stage


def _open_login_and_submit_email(
    settings: Settings,
    mailbox: dict,
    *,
    email: str,
    logger,
    label: str,
    entry_urls: tuple[str, ...] | None = None,
    signup: bool = False,
) -> str:
    """Clean the browser, walk the entry ladder, submit the address.

    Returns the stage the page landed on (``otp`` / ``password`` /
    ``create-account-password`` …). Shared by 登录 (existing accounts) and 注册
    (fresh smsbower addresses) because both need exactly this preamble, and it
    carries every hard-won workaround: the "你的会话已结束" interstitial, frame
    teardown mid-redirect, dead-end entries, and the tab-URL fallback that keeps
    a slow proxy from throwing away an OTP that really was sent.

    ``entry_urls`` MUST be the signup ladder for 注册: /log-in is the LOGIN page,
    and typing a fresh address there gets answered with "enter your password"
    instead of the signup verification code. See _SIGNUP_ENTRY_URLS.

    ``signup`` additionally forbids following the "你的会话已结束" page's 登录
    link — that link is a one-way door into the LOGIN flow.
    """
    logger.info("[Codex] %s：账号开始前清理浏览器（保持隐私模式）", label)
    if signup:
        notices.push("正在清理浏览器环境…", scope="signup")
    proxied = isinstance(mailbox.get("proxy"), dict)
    _bridge_apply_proxy(mailbox, label=label)
    _bridge_cleanup()
    # Walk the entry ladder (see _LOGIN_ENTRY_URLS): each entry gets one plain
    # reload before moving on, because a page that loaded but did not redirect
    # can only be fixed by a new request — and if the same URL fails twice, a
    # different entry is far more likely to help than a third identical try.
    email_result = None
    last_error = ""
    if entry_urls is None:
        entry_urls = _PROXY_LOGIN_ENTRY_URLS if proxied else _LOGIN_ENTRY_URLS
    # 注册只认真正的输入框；登录还要认「登录」链接（中转页本来就是靠点它过去的）。
    # 例外：注册入口是 chatgpt.com 首页时，那页一开始压根没有输入框（要先点右上角
    # 「Log in」才有），只等输入框就会白等满整个导航预算，所以按登录那套判据来。
    entry_via_chatgpt_home = tuple(bool(_CHATGPT_HOME_RE.match(url)) for url in entry_urls)
    ready_selector = _SIGNUP_READY_SELECTOR if signup else _LOGIN_READY_SELECTOR
    if signup and not any(entry_via_chatgpt_home):
        # auth.openai.com 的会话要靠一次经 chatgpt.com 的 OAuth 往返才建立得起来。
        # 清完 cookie 后直接 GET /create-account 跳过了这一步，OpenAI 只会回
        # is_missing_session 中转页——实测得盲目重发 4~5 次才碰上真表单，每次 3~11s。
        # 中转页自己就写着出路（"Continue by logging in" → chatgpt.com/auth/login_with），
        # 那条链接的作用正是种会话；而会话建成后 /create-account 是可直达的
        # （登录页上的 "Sign up" 链接 href 就是 /create-account）。
        # 所以先走一次 chatgpt.com 把会话种下——**只导航，不在那页做任何操作**，
        # 免得又被拖进登录流程——再进注册入口。
        logger.info("[Codex] %s：先经 chatgpt.com 建立 auth 会话，再进注册入口", label)
        notices.push("正在建立 OpenAI 会话…", scope="signup")
        try:
            _bridge_navigate(
                _LOGIN_WITH_URL,
                ready_selector=_LOGIN_READY_SELECTOR,
                retries=0,
                tolerate_timeout=True,
                # 预热只要一次 HTTP 往返把 cookie 种下，不需要页面渲染完。给足
                # 45s 的完整导航预算在慢代理下会白等满——实测预热+入口两次导航
                # 一共烧掉 120s。这里给一个短预算，超时就直接往下走。
                timeout=_SIGNUP_WARMUP_TIMEOUT,
            )
        except RuntimeError as exc:
            # 种会话失败不致命：下面的入口阶梯本来就有重试兜底。
            logger.warning("[Codex] %s：预热会话失败，直接试注册入口：%s", label, str(exc)[:160])
        if proxied:
            time.sleep(_PROXY_SETTLE_SECONDS)
    for entry_index, entry_url in enumerate(entry_urls):
        if entry_index:
            logger.warning("[Codex] %s：换用入口 %s", label, entry_url)
        # chatgpt.com 首页作为注册入口时，"就绪"只能按登录那套判（见上）。
        via_chatgpt_home = entry_via_chatgpt_home[entry_index]
        entry_ready_selector = _LOGIN_READY_SELECTOR if via_chatgpt_home else ready_selector
        if signup and via_chatgpt_home:
            logger.info(
                "[Codex] %s：从 chatgpt.com 首页进入并点右上角「Log in」提交邮箱", label
            )
        _bridge_navigate(
            entry_url,
            # Stop waiting as soon as something clickable exists. chatgpt.com is
            # a long-polling SPA: behind a proxy the tab can stay in 'loading'
            # essentially forever while the header (with its Log in button) is
            # already usable, which produced an endless "标签页加载超时" retry
            # loop. submit_email does its own waiting and clicking, so it — not
            # the load event — decides when the page is ready.
            ready_selector=entry_ready_selector,
            retries=0 if proxied else 2,
            tolerate_timeout=True,
        )
        if proxied:
            # Still give Cloudflare's JS detection and the sentinel iframe a
            # moment before touching anything.
            time.sleep(_PROXY_SETTLE_SECONDS)
        reloaded_this_entry = False
        reseed_rounds = 0
        # No fixed sleep here: the navigate above already returned because the
        # email box (or the 登录 control) is on screen, and submit_email waits
        # for it again anyway. A blanket sleep was pure dead time per account.
        for entry_attempt in range(1, _LOGIN_CLICK_ROUNDS + 1):
            try:
                if signup:
                    notices.push(f"正在提交邮箱 {email}…", scope="signup")
                email_result = _bridge_page_action("submit_email", email=email)
                break
            except RuntimeError as exc:
                msg = str(exc)
                last_error = msg
                if _RISK_BLOCK_TOKEN in msg:
                    raise
                # 风控甩去 accounts.google.com 是跨域跳转，会把注入帧一起销毁，
                # 于是报上来的是"帧销毁"——正好落进下面的可重试分支，白白再试 6 轮。
                # 只在这一种情况下多读一次标签页 URL：其它错误页面还在 OpenAI 域内，
                # 没必要为此给每次重试都加一个桥接往返（登录路径的调用序列也有断言）。
                if signup and _is_frame_teardown_error(msg):
                    blocked_url = _third_party_idp_url()
                    if blocked_url:
                        raise _risk_block_failure(blocked_url) from exc
                # Still on "你的会话已结束" with a 登录 control, or the click we just
                # made tore the frame down mid-navigation. Both mean "we are
                # making progress, run the step again" — it starts by clicking.
                click_again = _LOGIN_RETRY_CLICK_TOKEN in msg or _is_frame_teardown_error(msg)
                dead_end = any(token in msg for token in _LOGIN_ENTRY_DEAD_END)
                timed_out = bool(re.search(r"标签页加载超时|超时", msg))
                if _NO_EMAIL_BOX_TOKEN in msg:
                    # "没有邮箱框"不等于"这个入口是死路"——页面很可能**已经走过
                    # 邮箱这一步了**。实测：点回中转页的登录控件后 OpenAI 直接把我们
                    # 送回 /email-verification（Check your inbox +「Continue with
                    # password」），那页当然没有邮箱框；旧代码把它当死路重新加载入口，
                    # 等于把已经拿到的进度扔掉，还白烧一个取号。
                    # 只读标签页 URL：不注入、不受页面语言影响（同踩坑 #12）。
                    landed = _wait_for_post_email_landing(logger, label, timeout=3.0)
                    if landed:
                        logger.info(
                            "[Codex] %s：页面其实已经走过邮箱步骤（阶段 %s），不再重进入口",
                            label,
                            landed,
                        )
                        email_result = {"next_stage": landed}
                        break
                if not (click_again or dead_end or timed_out):
                    raise
                if entry_attempt >= _LOGIN_CLICK_ROUNDS:
                    break
                if click_again:
                    if signup and not via_chatgpt_home:
                        # 注册模式绝不能跟着「Log in」走：清完 cookie 后
                        # /create-account 会先渲染成"你的会话已结束"，而那页唯一的
                        # 控件是 Log in → chatgpt.com/auth/login_with，点下去整条
                        # 流程就从"注册"被拖进"登录"，后面拿到的是登录版
                        # /email-verification，它的「Continue with password」去的是
                        # /log-in/password 而不是 /create-account/password。
                        #
                        # 但也别对同一个地址盲发：中转页说明会话还没建起来，重发
                        # 只是碰运气（实测要 4~5 次）。经 chatgpt.com 再种一次会话，
                        # 然后才回注册入口——只导航、不点它页面上的任何东西。
                        #
                        # 入口本来就是 chatgpt.com 首页时**不走这套**：那里的
                        # 「Log in」进的是二合一弹窗（Log in or sign up），点它正是
                        # 我们要的动作；这时 login_retry_click 多半来自弹窗默认的
                        # 手机号表单，重跑 submit_email（它开头就会点
                        # 「Continue with email」）才是对的恢复方式。
                        logger.info(
                            "[Codex] %s：注册入口仍是会话中转页，经 chatgpt.com 重新种会话后再进 %s",
                            label,
                            entry_url,
                        )
                        reseed_rounds += 1
                        if reseed_rounds > _SIGNUP_RESEED_ROUNDS:
                            # 种会话对这个入口无效（实测 /create-account 已经彻底
                            # 拿不到注册表单），继续重发只是每轮白等 4~11s。
                            logger.warning(
                                "[Codex] %s：入口 %s 连续 %d 轮都停在会话中转页，换下一个入口",
                                label,
                                entry_url,
                                reseed_rounds,
                            )
                            break
                        try:
                            _bridge_navigate(
                                _LOGIN_WITH_URL,
                                ready_selector=_LOGIN_READY_SELECTOR,
                                retries=0,
                                tolerate_timeout=True,
                            )
                        except RuntimeError as warm_exc:
                            logger.warning(
                                "[Codex] %s：重新种会话失败：%s", label, str(warm_exc)[:160]
                            )
                        _bridge_navigate(
                            entry_url,
                            ready_selector=entry_ready_selector,
                            retries=0 if proxied else 1,
                            tolerate_timeout=True,
                        )
                        continue
                    logger.info(
                        "[Codex] %s：页面还停在登录中转页，再点一次登录重新进入流程（第 %d 次）：%s",
                        label,
                        entry_attempt + 1,
                        msg[:200],
                    )
                    continue
                if dead_end:
                    if reloaded_this_entry:
                        # Reloading this URL already failed once; a different
                        # entry is far more likely to help than a third try.
                        break
                    reloaded_this_entry = True
                    logger.warning(
                        "[Codex] %s：入口 %s 未落到邮箱表单，重新加载后再试一次",
                        label,
                        entry_url,
                    )
                    try:
                        _bridge_reload(ready_selector=entry_ready_selector)
                    except RuntimeError as reload_exc:
                        logger.warning("[Codex] %s：重新加载失败：%s", label, str(reload_exc)[:120])
                        break
                    continue
                logger.warning("[Codex] %s：登录页仍在跳转，1s 后重试提交邮箱：%s", label, msg[:120])
                time.sleep(1.0)
        if email_result is not None:
            if entry_index:
                logger.info("[Codex] %s：登录入口 %s 生效", label, entry_url)
            break
    if email_result is None:
        raise RuntimeError(
            f"[Codex] {label}：{len(entry_urls)} 个登录入口都没能进入邮箱表单"
            f"（最后一次：{last_error[:200]}）。"
            "页面能打开但进不到邮箱输入框，通常是出口 IP 被区别对待，试试关闭代理池或换一条住宅代理。"
        )
    if email_result is None:
        raise RuntimeError(f"[Codex] {label}：未能进入邮箱登录页")
    email_stage = str(email_result.get("next_stage") or "").strip().lower()
    logger.info("[Codex] %s：提交邮箱后进入阶段：%s", label, email_stage or "unknown")
    if not email_stage:
        # The in-page check gave up, but that check lives inside one document and
        # only understands the languages hardcoded in it. Before writing the run
        # off, watch the tab itself — a slow proxy can land /email-verification
        # after the judgement window closed, and killing the job there throws
        # away an OTP that was actually sent.
        email_stage = _wait_for_post_email_landing(logger, label)
    if not email_stage:
        # Nothing on the page said "an OTP was sent" (no code inputs, no
        # /email-verification, no password page…). Historically we polled the
        # mailbox anyway and, 90s later, failed with "等待通用 API 验证码超时；
        # HTTP 200 但未提取到验证码" — which blames the mailbox for a mail that was
        # never sent and hides where the browser actually ended up. Dump the page
        # and stop now: the account can be retried, and the log finally names the
        # real page.
        state = email_result.get("state") if isinstance(email_result.get("state"), dict) else {}
        buttons = ", ".join(
            str(item.get("text") or "").strip()
            for item in (state.get("buttons") or [])
            if isinstance(item, dict) and str(item.get("text") or "").strip()
        )
        logger.warning(
            "[Codex] %s：提交邮箱后落到未识别页面 url=%s title=%s headings=%s buttons=%s",
            label,
            state.get("url") or "",
            state.get("title") or "",
            " | ".join(str(item) for item in (state.get("headings") or []))[:200],
            buttons[:300],
        )
        logger.warning("[Codex] %s：页面文本：%s", label, str(state.get("body_preview") or "")[:500])
        raise RuntimeError(
            f"[Codex] {label}：提交邮箱后落到未识别页面（{str(state.get('url') or '')[:120]}"
            f" / {str(state.get('title') or '')[:60]}），验证码很可能没有发出，已提前结束以免空等取码。"
        )
    return email_stage


def _login_account_in_browser(
    settings: Settings,
    mailbox: dict,
    *,
    otp_provider,
    password: str = "",
    totp_provider=None,
    label: str = "登录",
) -> tuple[object, str, dict | None]:
    """Log the account into ChatGPT (email + email OTP, or password + TOTP).

    This does NOT run the Codex OAuth authorize flow — no phone verification, no
    consent, no SMS. Returns ``(codex_oauth_module, email, session)`` once the
    account is logged in; raises on any failure.
    """
    codex_oauth = _ensure_upstream_imports(settings)
    logger = codex_oauth.logger
    email = str(mailbox.get("email") or "").strip()
    password_totp_login = str(mailbox.get("source") or "").strip().lower() == "password_totp"
    email_stage = _open_login_and_submit_email(
        settings, mailbox, email=email, logger=logger, label=label
    )

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


# ------------------------------------------------------------- smsbower-gmail 注册
# The only path in this repo that CREATES an account. A gmail address rented
# from smsbower is registered on chatgpt.com, given a generated password, and
# verified with the code the rental delivers. 不接码（短信）、不走 OAuth.
_REGISTER_FAILED_TOKEN = "register_failed"
# 地址已经有账号了：既注册不了、我们也没有它的密码登录不进去，直接放弃。
# 单独一个令牌，好让调度器分类成"已注册帐号"而不是笼统的注册失败。
_ACCOUNT_EXISTS_TOKEN = "account_already_registered"
_REGISTER_PASSWORD_LENGTH = 12
_CHATGPT_URL_RE = re.compile(r"^https?://([^/]*\.)?chatgpt\.com(/|$)", re.I)


def _generate_register_password(length: int = _REGISTER_PASSWORD_LENGTH) -> str:
    """A 12-char password of letters and digits only.

    Deliberately narrower than :func:`_generate_signup_password`: the需求 spells
    out "仅包含大小写字母、数字", and this password is exported as the middle
    column of ``email----密码----密钥``, where a ``----`` or ``|`` in the value
    would corrupt the line.
    """

    size = max(8, int(length))
    alphabet = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(size))
        if (
            any(char.islower() for char in password)
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
        ):
            return password


class _RegisterStopped(Exception):
    """The operator pressed 停止后续任务 during a long wait."""


def _raise_if_stopped(cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise _RegisterStopped()


def _register_failure(message: str) -> RuntimeError:
    """Terminal registration failure: the rental is spent, retrying wastes another."""

    return RuntimeError(f"[Codex] {_REGISTER_FAILED_TOKEN}：{message}")


def _account_exists_failure(email: str, where: str) -> RuntimeError:
    """The address already has an OpenAI account — abandon it, never retry.

    只有在**已经走了注册入口 /create-account** 的前提下落到登录密码页，才能这么
    判。历史上注册误用了 /log-in（登录页），任何全新地址都会被回「输入密码」，
    当时把它读成"已注册"是误判，会把好号白白丢掉。改判据前先确认入口是对的。
    """

    return RuntimeError(
        f"[Codex] {_ACCOUNT_EXISTS_TOKEN}：已注册帐号 —— {email} 已存在 OpenAI 账号（{where}），放弃该账号"
    )


def _smsbower_mail_runtime(settings: Settings):
    from .smsbower_mail import SmsbowerMailClient
    from .smsbower_mail_store import SmsbowerMailConfigStore

    config = SmsbowerMailConfigStore(Path(settings.data_dir)).get()
    if not config.get("api_key"):
        raise _register_failure("smsbower 邮箱 API Key 尚未配置")
    return SmsbowerMailClient(config["api_key"]), config


def _wait_for_smsbower_code(
    logger,
    client,
    mail_id: int,
    *,
    timeout: float,
    interval: float,
    exclude: list[str],
    label: str,
    cancel_event=None,
) -> str:
    """Poll ``getCode`` until a code the caller has not tried yet shows up.

    Returns "" on timeout — the caller decides whether that ends the account.
    A provider hiccup is logged and retried; only a dead activation aborts,
    because polling a cancelled rental can never succeed.

    Raises ``_RegisterStopped`` when the user stops the pipeline: this loop can
    run for two full codeTimeout windows, and a worker thread cannot be
    force-killed, so without this cooperative check "停止后续任务" appears dead.
    """

    from .smsbower_mail import (
        SmsbowerMailActivationGoneError,
        SmsbowerMailCodePendingError,
        SmsbowerMailError,
    )

    started = time.time()
    deadline = started + max(1.0, float(timeout))
    attempt = 0
    while time.time() < deadline:
        _raise_if_stopped(cancel_event)
        attempt += 1
        # 每一轮都往侧边栏推一条：取码是这条流水线里最长的一段静默期，
        # 不报进度用户只能干等，也分不清"还没到"和"卡死了"。
        elapsed = int(time.time() - started)
        remaining = max(0, int(deadline - time.time()))
        try:
            code = client.fetch_code(mail_id)
        except SmsbowerMailCodePendingError:
            code = ""
            notices.push(
                f"取码第 {attempt} 次：验证码还没到（已等 {elapsed}s，剩 {remaining}s）",
                scope="smsbower",
            )
        except SmsbowerMailActivationGoneError as exc:
            notices.push(f"取码失败：{exc}", level="error", scope="smsbower")
            raise _register_failure(str(exc)) from exc
        except SmsbowerMailError as exc:
            logger.warning("[Codex] %s：取码接口异常，继续等待：%s", label, str(exc)[:160])
            notices.push(
                f"取码第 {attempt} 次：接口异常，继续等待（{str(exc)[:80]}）",
                level="warn",
                scope="smsbower",
            )
            code = ""
        if code and code in exclude:
            notices.push(
                f"取码第 {attempt} 次：拿到的还是上一轮那枚旧码，继续等新码",
                level="warn",
                scope="smsbower",
            )
        if code and code not in exclude:
            logger.info("[Codex] %s：已收到验证码", label)
            notices.push(f"取码成功：{code}（用时 {elapsed}s）", level="success", scope="smsbower")
            return code
        # Sleep in short slices so a stop request lands within ~1s instead of
        # waiting out a full poll interval.
        slept = 0.0
        step = min(1.0, max(0.1, float(interval)))
        while slept < max(1.0, float(interval)):
            _raise_if_stopped(cancel_event)
            time.sleep(step)
            slept += step
    notices.push(
        f"取码超时：{int(timeout)}s 内没有收到新的验证码", level="error", scope="smsbower"
    )
    return ""


def _wait_for_register_landing(logger, label: str, *, timeout: float = 30.0) -> str:
    """Watch the tab's own URL after an OTP/about-you submit.

    Submitting can tear the injected frame down mid-navigation, so the in-page
    answer is often lost. The tab URL survives that and is immune to the page's
    language.
    """

    interval = 1.0
    for _ in range(max(1, int(max(1.0, timeout) / interval))):
        result = _bridge_request("tab_url", {}, timeout=20.0, raise_on_error=False)
        url = str(result.get("url") or "").lower()
        if "/about-you" in url:
            return "about-you"
        if _CHATGPT_URL_RE.match(url):
            return "chatgpt"
        if "/email-verification" in url:
            return "otp"
        if "/create-account/password" in url:
            return "create-account-password"
        if "/phone-verification" in url or "/add-phone" in url:
            return "phone"
        time.sleep(interval)
    logger.info("[Codex] %s：标签页 URL 在 %ss 内没有变化", label, int(timeout))
    return ""


_PRICING_URL = "https://chatgpt.com/#pricing"
# 落到 /log-in/password 时最多用 Sign up 链接救回来几次。
_SIGNUP_RECOVER_ROUNDS = 2


# 点「Sign up」之后的落点。/create-account/password 必须排在 /create-account
# 前面——后者是前者的前缀，顺序反了会把设密码页认成邮箱表单再白提交一次邮箱。
_SIGNUP_LINK_URLS = (
    ("/create-account/password", "create-account-password"),
    ("/email-verification", "otp"),
    ("/create-account", "create-account"),
)


def _click_signup_link(logger, *, label: str) -> dict:
    """点登录密码页底部的「Sign up」回到注册流程。

    又是一个"点了就会跳页"的步骤：导航会销毁注入帧，`Frame with ID X was removed`
    和静默的"页面动作返回空结果"都代表**点成功了**，不能当失败。
    """

    try:
        return _bridge_page_action("click_signup_link")
    except RuntimeError as exc:
        if not _is_frame_teardown_error(exc) and "浏览器桥接超时" not in str(exc):
            raise
        logger.info(
            "[Codex] %s：点「Sign up」后注入帧被销毁（页面正在跳转），改读标签页 URL 判落点：%s",
            label,
            str(exc)[:160],
        )
        stage = _wait_for_tab_stage(
            logger, label, targets=_SIGNUP_LINK_URLS, timeout=25.0, step="点「Sign up」"
        )
        if stage:
            return {"ok": True, "next_stage": stage, "frame_teardown": True}
        # 回不到注册流程就照实说；调用方会把它当"救不回来"处理，不会误判成已注册。
        return {"ok": True, "next_stage": "", "frame_teardown": True}


def _recover_signup_from_login_password(logger, *, label: str, email: str) -> str:
    """从 `/log-in/password` 点「Sign up」回到注册流程，并重新提交邮箱。

    该页底部有 `Don't have an account? <a href="/create-account">Sign up</a>`
    （快照 1038377682-…-175759），点它就回到真正的注册入口——比把账号判死刑好得多。
    返回重新提交邮箱后的阶段；救不回来时返回 ""。
    """

    result = _click_signup_link(logger, label=label)
    if result.get("signup_link_missing"):
        logger.warning("[Codex] %s：登录密码页上没有「Sign up」链接，无法回到注册流程", label)
        return ""
    stage = str(result.get("next_stage") or "").strip().lower()
    logger.info("[Codex] %s：已点「Sign up」回到注册流程，当前阶段：%s", label, stage or "unknown")
    if stage == "create-account-password":
        # 已经直接落到设密码页，不用再提交邮箱。
        return stage
    if stage == "otp":
        return stage
    # 落在 /create-account 的邮箱表单上：重新提交一次邮箱。
    email_result = _submit_login_step(
        "submit_email", label=label, step="重新提交邮箱", logger=logger, email=email
    )
    new_stage = str(email_result.get("next_stage") or "").strip().lower()
    if not new_stage:
        new_stage = _wait_for_post_email_landing(logger, label)
    logger.info("[Codex] %s：回到注册流程后提交邮箱，进入阶段：%s", label, new_stage or "unknown")
    return new_stage


def _probe_plus_trial(logger, *, label: str) -> bool:
    """注册成功后看 chatgpt.com/#pricing 顶部有没有「Try Plus free for 1 month」。

    纯只读探测，不点任何东西。账号此时已经建成，所以这里**任何失败都只降级成
    "没有资格"并 warning**，绝不把一个注册成功的账号判失败。
    """

    try:
        # 已经在 chatgpt.com 上时这是一次 hash 跳转，标签页不会重新加载，所以
        # 允许超时——真正判断"页面渲染出来没有"的是探测动作自己。
        _bridge_navigate(_PRICING_URL, tolerate_timeout=True, retries=0)
        result = _bridge_page_action("probe_plus_offer")
    except RuntimeError as exc:
        logger.warning("[Codex] %s：Plus 免费资格探测失败，按无资格记录：%s", label, str(exc)[:200])
        return False
    value = result.get("plus_trial")
    if value is None:
        logger.warning(
            "[Codex] %s：#pricing 页面没渲染出来（url=%s），无法确认 Plus 资格，按无资格记录",
            label,
            str(result.get("url") or "")[:120],
        )
        return False
    if value:
        logger.info(
            "[Codex] %s：检测到 Plus 免费资格：%s", label, str(result.get("matched_text") or "")[:80]
        )
    return bool(value)


_SECURITY_SETTINGS_URL = "https://chatgpt.com/#settings/Security"
# 开启 MFA 时可能被要求重新验证身份，验证完要回到设置页再开一次。
_MFA_ROUNDS = 2
# 读 Base32 密钥的重试轮数（每轮内部扩展自己还会点 3 次「Trouble scanning?」）。
_MFA_REVEAL_ROUNDS = 3
# 自动读取和二维码都失败之后，等人工把密钥显示出来的总时长与轮询间隔。
# **绝不允许跳过这一步去跑下一个账号**：密钥只显示这一次，跳过 = 账号作废。
# 唯一的出口是用户自己点「停止后续任务」（cancel_event），或者等满这个时长。
_MFA_MANUAL_WAIT_SECONDS = 1800.0
_MFA_MANUAL_POLL_SECONDS = 5.0
# 人工等待也超时了才会带上这个令牌。用它把"还没求助过人"和"人也没来"区分开：
# 前者要转人工，后者再等一个 30 分钟没有任何意义。
_MFA_MANUAL_TIMEOUT_TOKEN = "mfa_manual_wait_timeout"


def _safe_totp_secret(value: str) -> str:
    """把页面读到的东西规范成 Base32 密钥；不合法就返回 ""（不抛错）。"""

    try:
        return normalize_totp_secret(str(value or ""))
    except Exception:
        return ""


def _secret_from_otpauth(uri: str) -> str:
    """从 `otpauth://totp/...?secret=XXXX` 里取出密钥。"""

    match = re.search(r"[?&]secret=([A-Za-z2-7=]+)", str(uri or ""), re.I)
    return _safe_totp_secret(match.group(1)) if match else ""


def _decode_totp_qr(data_url: str, *, logger, label: str) -> str:
    """把二维码图片解码成 otpauth:// 里的 Base32 密钥。

    可选依赖，按可用性依次尝试 opencv → pyzbar；两个都没装就照实说清楚该装什么，
    再交给人工兜底——绝不静默失败。
    """

    raw = _decode_image_data_url(data_url)
    if not raw:
        return ""
    # opencv：pip 一条命令就能装，Windows 上不需要额外的原生依赖。
    try:
        import numpy  # type: ignore
        import cv2  # type: ignore

        image = cv2.imdecode(numpy.frombuffer(raw, dtype=numpy.uint8), cv2.IMREAD_GRAYSCALE)
        if image is not None:
            detector = cv2.QRCodeDetector()
            for candidate in (image, cv2.bitwise_not(image)):
                # 深色模式下二维码是反相的，两种都试一遍。
                text = detector.detectAndDecode(candidate)[0]
                secret = _secret_from_otpauth(text) or _safe_totp_secret(text)
                if secret:
                    logger.info("[Codex] %s：opencv 解出了二维码", label)
                    return secret
    except ImportError:
        logger.warning(
            "[Codex] %s：没装 opencv，无法解二维码（pip install opencv-python-headless）", label
        )
    except Exception as exc:  # 解码器自身出错不该影响后续兜底
        logger.warning("[Codex] %s：opencv 解二维码失败：%s", label, str(exc)[:160])
    try:
        import io

        from PIL import Image, ImageOps  # type: ignore
        from pyzbar.pyzbar import decode as zbar_decode  # type: ignore

        image = Image.open(io.BytesIO(raw)).convert("L")
        for candidate in (image, ImageOps.invert(image)):
            for item in zbar_decode(candidate):
                text = item.data.decode("utf-8", errors="replace")
                secret = _secret_from_otpauth(text) or _safe_totp_secret(text)
                if secret:
                    logger.info("[Codex] %s：pyzbar 解出了二维码", label)
                    return secret
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("[Codex] %s：pyzbar 解二维码失败：%s", label, str(exc)[:160])
    return ""


def _decode_image_data_url(data_url: str) -> bytes:
    """`data:image/png;base64,....` → 原始字节。"""

    value = str(data_url or "")
    if "," not in value or not value.lower().startswith("data:"):
        return b""
    try:
        return base64.b64decode(value.split(",", 1)[1], validate=False)
    except (ValueError, binascii.Error):
        return b""


def _secret_from_qr(logger, *, label: str) -> str:
    """截下 MFA 弹窗里的二维码并解码。任何一步失败都只 warning，交给人工兜底。"""

    try:
        shot = _bridge_page_action("mfa_capture_qr", timeout=60.0, raise_on_error=False)
    except RuntimeError as exc:
        logger.warning("[Codex] %s：二维码截图失败：%s", label, str(exc)[:160])
        return ""
    if not shot.get("ok"):
        logger.warning("[Codex] %s：二维码截图失败：%s", label, str(shot.get("error") or "")[:160])
        return ""
    return _decode_totp_qr(str(shot.get("qr_image") or ""), logger=logger, label=label)


def _reveal_totp_secret(logger, *, label: str, cancel_event=None) -> str:
    """拿到 Base32 密钥。**这一步绝不轻易放弃**：

      3 轮"点 Trouble scanning? + 读页面" → 解二维码 → 转人工等待。

    OpenAI 这串密钥只显示这一次，读不到就等于这个账号废掉，所以宁可卡在这里等人，
    也绝不跳过去跑下一个账号。
    """

    last_reason = ""
    for attempt in range(1, _MFA_REVEAL_ROUNDS + 1):
        _raise_if_stopped(cancel_event)
        try:
            result = _bridge_page_action("mfa_reveal_secret")
        except RuntimeError as exc:
            last_reason = str(exc)
            logger.warning(
                "[Codex] %s：第 %d/%d 次读取 2FA 密钥出错：%s",
                label,
                attempt,
                _MFA_REVEAL_ROUNDS,
                last_reason[:160],
            )
            time.sleep(2.0)
            continue
        secret = _safe_totp_secret(result.get("secret")) or _secret_from_otpauth(result.get("otpauth"))
        if secret:
            logger.info("[Codex] %s：第 %d 次尝试读到 2FA 密钥", label, attempt)
            return secret
        last_reason = "页面上没有显示 Base32 密钥"
        logger.warning(
            "[Codex] %s：第 %d/%d 次没读到 Base32 密钥，继续重试", label, attempt, _MFA_REVEAL_ROUNDS
        )
        notices.push(f"2FA 密钥没读到，正在重试（{attempt}/{_MFA_REVEAL_ROUNDS}）…", scope="mfa")
        time.sleep(2.0)

    _raise_if_stopped(cancel_event)
    logger.warning("[Codex] %s：%d 次都没读到 Base32 密钥，改为解析二维码", label, _MFA_REVEAL_ROUNDS)
    notices.push("2FA 密钥读不到，正在尝试解析二维码…", scope="mfa")
    secret = _secret_from_qr(logger, label=label)
    if secret:
        logger.info("[Codex] %s：已从二维码解出 2FA 密钥", label)
        return secret

    return _wait_for_manual_totp_secret(
        logger, label=label, cancel_event=cancel_event, reason=last_reason
    )


def _wait_for_manual_totp_secret(
    logger, *, label: str, cancel_event=None, reason: str = "", hint: str = ""
) -> str:
    """转人工：卡在这里等，**绝不跳过这个账号**。

    页面就停在 MFA 弹窗上（或停在设置页——自动流程更早的地方就失败时也走这里）。
    请在浏览器里把 32 位密钥显示出来，这里每 5s **只读一次页面、不点任何东西**
    （免得和人抢着点），一读到就自动接着往下走。要放弃只能按侧边栏的「停止后续任务」。
    """

    hint = hint or (
        "⚠ 需要手动操作：自动读取和二维码解码都失败了。请在浏览器的 2FA 弹窗里点"
        "「Trouble scanning?」把 32 位密钥显示出来，程序会自动读取并继续（不想等就点"
        "「停止后续任务」）"
    )
    logger.warning("[Codex] %s：%s（原因：%s）", label, hint, reason[:120] or "未知")
    notices.push(hint, scope="mfa")
    rounds = max(1, int(_MFA_MANUAL_WAIT_SECONDS / _MFA_MANUAL_POLL_SECONDS))
    for index in range(rounds):
        _raise_if_stopped(cancel_event)
        # read_only：只读不点，人在操作时不会被我们抢走焦点。
        result = _bridge_page_action("mfa_reveal_secret", read_only=True, raise_on_error=False)
        secret = _safe_totp_secret(result.get("secret")) or _secret_from_otpauth(result.get("otpauth"))
        if secret:
            logger.info("[Codex] %s：已读到人工显示出来的 2FA 密钥，继续往下走", label)
            notices.push("已读到 2FA 密钥，继续自动执行", scope="mfa")
            return secret
        # 每分钟再顺手试一次二维码：用户可能把弹窗切回了二维码视图。
        if index and index % 12 == 0:
            secret = _secret_from_qr(logger, label=label)
            if secret:
                logger.info("[Codex] %s：等待期间从二维码解出了 2FA 密钥", label)
                return secret
            waited = int(index * _MFA_MANUAL_POLL_SECONDS)
            logger.warning("[Codex] %s：仍在等待人工显示 2FA 密钥（已等 %ds）", label, waited)
            notices.push(f"仍在等待手动显示 2FA 密钥（已等 {waited // 60} 分钟）…", scope="mfa")
        time.sleep(_MFA_MANUAL_POLL_SECONDS)
    raise RuntimeError(
        f"[Codex] {_MFA_MANUAL_TIMEOUT_TOKEN}：等待人工提供 2FA 密钥超时"
        f"（{int(_MFA_MANUAL_WAIT_SECONDS / 60)} 分钟）"
    )


def _run_mfa_enrollment(
    logger, *, label: str, password: str, on_secret=None, cancel_event=None
) -> str:
    """需求步骤 7-9：给刚注册好的账号开启验证器 App 并取回 Base32 密钥。

    #settings/Security → Security and login → Authenticator app
      → （可能的身份验证挑战：Continue with password + 刚生成的密码）
      → Trouble scanning? → 读密钥 → 用密钥算 TOTP 填回去 → Verify

    **这一整段任何一步失败都不会直接放弃**：密钥 OpenAI 只显示这一次，跳过去跑下
    一个账号就等于把这个账号废掉。所以自动流程一旦走不通（打不开设置、身份验证
    没过、弹窗没出来……）一律转人工等待（`_wait_for_manual_totp_secret`，30 分钟，
    期间只读不点），等人在浏览器里把密钥点出来再自动接上；用户按「停止后续任务」
    才是唯一的提前出口。
    """

    try:
        secret = _open_mfa_dialog_and_reveal(
            logger, label=label, password=password, cancel_event=cancel_event
        )
    except _RegisterStopped:
        raise
    except Exception as exc:
        reason = str(exc)
        if _MFA_MANUAL_TIMEOUT_TOKEN in reason:
            # 已经等过一轮人工了（密钥读取那步自己会转人工），别再等第二个 30 分钟。
            raise
        logger.warning("[Codex] %s：自动开启 2FA 走不通，转人工：%s", label, reason[:200])
        secret = _wait_for_manual_totp_secret(
            logger,
            label=label,
            cancel_event=cancel_event,
            reason=reason,
            hint=(
                "⚠ 需要手动操作：自动开启 2FA 失败（"
                + reason[:120]
                + "）。请在浏览器里手动打开 设置 → Security → Authenticator app，"
                "点「Trouble scanning?」把 32 位密钥显示出来，程序会自动读取并继续"
                "（不想等就点「停止后续任务」）"
            ),
        )
    # 立刻落盘 + 立刻写日志，**在提交验证码之前**。
    # 血的教训：原来等"提交验证码成功"才保存，而那一步曾经误判失败抛异常，密钥
    # 随异常一起丢了——账号的 2FA 已经真的开启，却再也拿不到密钥，等于账号废掉。
    # OpenAI 这串密钥**只显示这一次**，所以规则是：读到即持久化，绝不押在后续
    # 任何一步的成败上。日志里也留一份，这是本机单用户工具，密钥本来就会随素材导出。
    if on_secret is not None:
        on_secret(secret)
    logger.info("[Codex] %s：已取得 2FA 密钥并立即落盘：%s", label, secret)
    notices.push("已取得 2FA 密钥（已保存），正在提交验证码", scope="mfa")

    # current_totp 自带 min_valid_seconds=4：剩余有效期不足就先等下一轮，
    # 满足需求"有效时间小于 3 秒则继续等待下一轮验证码"。
    submitted = _submit_login_step(
        "mfa_submit_code",
        label=label,
        step="提交 2FA 验证码",
        logger=logger,
        code=current_totp(secret),
    )
    error = str(submitted.get("error_text") or "").strip()
    # 判据顺序很重要：先认"弹层已消失 = 成功"，再看错误文本。
    # 成功后 OpenAI 会弹「Authenticator app enabled」这类提示，它落在 [role=alert]
    # 区域里，早期被当成错误，把一个已经开好的 2FA 误报成"验证码未通过"。
    if submitted.get("verified") or submitted.get("frame_teardown"):
        logger.info("[Codex] %s：验证器 App 已开启", label)
        return secret
    if error:
        raise RuntimeError(f"[Codex] 2FA 验证码未通过：{error[:200]}")
    raise RuntimeError("[Codex] 提交 2FA 验证码后弹层仍未关闭，无法确认是否开启成功")


def _open_mfa_dialog_and_reveal(
    logger, *, label: str, password: str, cancel_event=None
) -> str:
    """自动路径：打开验证器弹窗并读出 Base32 密钥（失败抛异常，由调用方转人工）。"""

    stage = ""
    for attempt in range(1, _MFA_ROUNDS + 1):
        _bridge_navigate(_SECURITY_SETTINGS_URL, tolerate_timeout=True, retries=0)
        # 这次导航是整页刷新，"You're all set" 欢迎弹层会**重新弹出来**（它在 load
        # 之后才画出来）。必须先等它出现并点掉，再去操作设置页——否则整页被 inert，
        # 下面每一次点击都落空，还会被报成"点击 Authenticator app 后没弹出 MFA 弹窗"。
        _dismiss_blocking_dialog(logger, label=label, wait_ms=8000)
        opened = _submit_login_step(
            "open_mfa_enroll", label=label, step="打开 MFA 设置", logger=logger
        )
        stage = str(opened.get("next_stage") or "").strip().lower()
        logger.info("[Codex] %s：打开 MFA 设置后进入阶段：%s", label, stage or "unknown")
        if stage == "dialog":
            break
        if stage == "challenge":
            # 这里要的正是 /log-in/password —— 账号是我们自己刚建的，密码在手上。
            logger.info("[Codex] %s：开启 MFA 触发了身份验证，改用密码验证", label)
            notices.push("开启 MFA 触发身份验证，正在用刚设置的密码验证", scope="mfa")
            challenge = _submit_login_step(
                "mfa_password_challenge",
                label=label,
                step="MFA 密码验证",
                logger=logger,
                password=password,
            )
            challenge_error = str(challenge.get("error_text") or "").strip()
            if challenge_error:
                raise RuntimeError(f"[Codex] MFA 身份验证失败：{challenge_error[:200]}")
            if attempt >= _MFA_ROUNDS:
                raise RuntimeError("[Codex] MFA 身份验证后仍未能打开验证器设置")
            continue
        if attempt >= _MFA_ROUNDS:
            raise RuntimeError(f"[Codex] 打开 MFA 设置失败（阶段 {stage or 'unknown'}）")
        # 阶段不对**不代表没救**：欢迎弹层可能刚好又弹了一次、设置页还没渲染完。
        # 重新导航一轮再试，实在不行才由调用方转人工。
        logger.warning(
            "[Codex] %s：打开 MFA 设置返回阶段 %s，重新进设置页再试（第 %d/%d 轮）",
            label,
            stage or "unknown",
            attempt,
            _MFA_ROUNDS,
        )
        time.sleep(2.0)
    if stage != "dialog":
        raise RuntimeError("[Codex] 未能打开 MFA 设置弹窗")

    # 3 轮点击重试 → 解二维码 → 转人工等待。**读不到就一直卡在这里，绝不跳过**。
    return _reveal_totp_secret(logger, label=label, cancel_event=cancel_event)


def _dismiss_blocking_dialog(logger, *, label: str, wait_ms: int = 0) -> bool:
    """点掉注册完成后 chatgpt.com 弹的那个原生 <dialog>（"You're all set"）。

    它是 `showModal()` 打开的，会把页面其余部分置为 inert —— 不点掉，后面探 Plus
    资格和开 MFA 的每一次点击都会点空。纯善后动作，失败只 warning。

    ``wait_ms``：**等它出现**再点。它是 React 的 blocking initial modal，在页面
    load 之后才画出来，每次整页刷新还会重新弹一次；只在调用的那一瞬间看一眼多半
    看不到（踩过坑：这里悄悄返回"没有弹层"，MFA 于是全程点空，最后报成"点击
    Authenticator app 后没弹出 MFA 弹窗"，真因被藏了整整一轮）。

    返回"页面当前没有被弹层挡住"。
    """

    try:
        result = _bridge_page_action("dismiss_blocking_dialog", wait_ms=int(wait_ms))
    except RuntimeError as exc:
        logger.warning("[Codex] %s：关闭欢迎弹层失败（继续往下走）：%s", label, str(exc)[:160])
        return False
    if result.get("dismissed"):
        logger.info(
            "[Codex] %s：已点掉注册完成后的欢迎弹层（%s 个）",
            label,
            result.get("dismissed_count") or 1,
        )
    if result.get("still_blocked"):
        # 这条一定要打：弹层没关掉时后面每一次点击都是点在 inert 页面上。
        logger.warning(
            "[Codex] %s：欢迎弹层「%s」仍在且点不掉，后续点击会被挡住",
            label,
            str(result.get("blocking_label") or "")[:60],
        )
        return False
    if not result.get("dismissed"):
        # 也要打：以前这里什么都不打，日志上看不出"到底查过没有"。
        logger.info("[Codex] %s：当前没有需要关闭的欢迎弹层", label)
    return True


def _run_account_signup(settings: Settings, mailbox: dict, *, cancel_event=None) -> dict:
    """Register one rented smsbower gmail on chatgpt.com (需求步骤 1-6).

    email → /email-verification → Continue with password → 设密码 → 邮箱验证码 →
    /about-you → chatgpt.com. No SMS, no OAuth, no phone verification.

    ``cancel_event`` makes 停止后续任务 take effect during the two codeTimeout
    windows: a worker thread cannot be force-killed, so every long wait polls it.
    """

    from .smsbower_mail import MAIL_STATUS_CANCEL, MAIL_STATUS_FINISH, MAIL_STATUS_NEXT_CODE

    try:
        codex_oauth = _ensure_upstream_imports(settings)
    except Exception:
        # 连上游模块都加载不了：账号一步都没跑，把号退回去，别让它空转计费。
        _settle_mailbox_rental(settings, mailbox, reason="上游模块加载失败，注册无法开始")
        raise
    logger = codex_oauth.logger
    label = "注册"
    email = str(mailbox.get("email") or "").strip()
    try:
        mail_id = int(str(mailbox.get("mail_id") or "").strip())
    except ValueError:
        mail_id = 0
    if mail_id <= 0:
        raise _register_failure(f"账号 {email} 没有 smsbower 活动 id，无法取码")

    try:
        client, config = _smsbower_mail_runtime(settings)
    except Exception as exc:
        # 客户端都建不起来（多半是 API Key 没配）：这个号**没法结算**，会一直计费。
        # 说清楚，别让它悄悄消失在一条通用报错里。
        logger.warning(
            "[Codex] %s：smsbower 客户端不可用，mail_id=%s 无法执行 setStatus，"
            "该邮箱可能仍在计费，请到 smsbower 后台手动关闭：%s",
            label,
            mail_id,
            str(exc)[:160],
        )
        raise
    store = MailboxStore(Path(settings.data_dir))
    code_timeout = float(config["code_timeout_seconds"])
    code_interval = float(config["code_interval_seconds"])
    password = _generate_register_password()
    # 重跑的账号：上一轮可能已经把号建出来并设过密码（`update_registration` 在提交
    # 密码**之前**就落盘了，正是为这一刻）。OpenAI 记得那个密码，所以本轮必须沿用
    # 它——另生成一个新密码就再也登不进这个已存在的账号了。
    known_password = str((store.get_secret(email=email) or {}).get("password") or "").strip()
    if known_password:
        password = known_password
        logger.info("[Codex] %s：该地址已存有上一轮设置的密码，本轮沿用它", label)
    # Cancel unless the account actually gets created: an activation left open
    # keeps billing, and status=3 on a failed run would pay for nothing.
    release_status = MAIL_STATUS_CANCEL
    try:
        _raise_if_stopped(cancel_event)
        email_stage = _open_login_and_submit_email(
            settings,
            mailbox,
            email=email,
            logger=logger,
            label=label,
            # 关键：走注册入口 /create-account，不是登录入口 /log-in。
            # 代理下例外：auth.openai.com 拿不到注册表单，改从 chatgpt.com 首页点
            # 右上角「Log in」进二合一弹窗（见 _PROXY_SIGNUP_ENTRY_URLS）。
            entry_urls=_signup_entry_urls(mailbox),
            signup=True,
        )
        _raise_if_stopped(cancel_event)
        logger.info("[Codex] %s：提交邮箱后进入阶段：%s", label, email_stage or "unknown")

        # 落到 /log-in/password 有两种情况，处理方式**完全相反**：
        #   a) 这个地址上一轮已经被我们建过号、也设过密码（重跑）——OpenAI 记得那个
        #      密码，把**存下来的那个**填回去就行，填对之后它要求邮箱验证，下一步
        #      正好就是 /email-verification，接回原本的取码流程。把它判死刑等于白扔
        #      一个已经建好的账号，还白烧一个取号。
        #   b) 从没建过号——那是被拖进了登录流程，点该页底部的
        #      `Don't have an account? Sign up`（href=/create-account）回注册流程。
        # 两个可能落点（提交邮箱后、点 Continue with password 后）共用这套判断。
        resumed_with_password = False
        if email_stage == "login-password" and known_password:
            email_stage = _resume_with_known_password(
                logger, label=label, email=email, password=password
            )
            resumed_with_password = email_stage == "otp"
        for _ in range(_SIGNUP_RECOVER_ROUNDS):
            if email_stage != "login-password":
                break
            _raise_if_stopped(cancel_event)
            logger.info("[Codex] %s：落到了登录密码页，点「Sign up」回到注册流程", label)
            email_stage = _recover_signup_from_login_password(logger, label=label, email=email)
        if email_stage == "login-password":
            raise _register_failure(
                "反复落到登录密码页，点「Sign up」也回不到注册流程，放弃该账号"
            )
        if email_stage not in {"otp", "create-account-password"}:
            # 需求步骤 2：只有落到 /email-verification 才是一个可注册的新地址。
            # 其它阶段一律判不了，这个号就作废。
            raise _register_failure(
                f"提交邮箱后没有进入验证码页（阶段 {email_stage or 'unknown'}），放弃该账号"
            )

        if email_stage == "otp" and not resumed_with_password:
            logger.info("[Codex] %s：切换到密码注册", label)
            notices.push("已到验证码页，正在切换到密码注册…", scope="signup")
            switch_stage = _switch_to_password_signup(logger, label=label)
            # 需求步骤 3 必须导向 /create-account/password。落到 /log-in/password
            # 说明这个号已经存在——密码在手上就直接登录，没有才用 Sign up 救回来。
            if switch_stage == "login-password" and known_password:
                switch_stage = _resume_with_known_password(
                    logger, label=label, email=email, password=password
                )
                resumed_with_password = switch_stage == "otp"
            for _ in range(_SIGNUP_RECOVER_ROUNDS):
                if switch_stage != "login-password":
                    break
                _raise_if_stopped(cancel_event)
                logger.info(
                    "[Codex] %s：「Continue with password」落到登录密码页，点「Sign up」回到注册流程",
                    label,
                )
                recovered = _recover_signup_from_login_password(logger, label=label, email=email)
                if recovered == "create-account-password":
                    switch_stage = recovered
                    break
                if recovered == "otp":
                    switch_stage = _switch_to_password_signup(logger, label=label)
                    continue
                switch_stage = recovered
            if not resumed_with_password and switch_stage != "create-account-password":
                raise _register_failure(
                    f"切换密码注册后进入了 {switch_stage or 'unknown'} 页（需要 /create-account/password）"
                )

        if resumed_with_password:
            # 密码本来就是这个账号的，不用再设一次；页面已经在 /email-verification 上。
            logger.info("[Codex] %s：已用已存密码登录，跳过设置密码，直接等邮箱验证码", label)
            notices.push("已用已存密码登录，正在等待邮箱验证码…", scope="signup")
            store.update_registration(
                email, status="pending", password=password, message="沿用已存密码，等待验证码"
            )
        else:
            logger.info("[Codex] %s：设置账号密码", label)
            # 慢代理下这一步实测能跑到 110s，是整条流水线最长的静默段之一。
            notices.push("正在设置账号密码（慢代理下可能要 1-2 分钟）…", scope="signup")
            # Persist before submitting: if the submit succeeds but this process dies
            # right after, an account exists whose password would otherwise be lost.
            store.update_registration(email, status="pending", password=password, message="已生成密码，等待验证码")
            password_result = _submit_signup_password(logger, label=label, password=password)
            password_error = str(password_result.get("error_text") or "").strip()
            if password_error:
                # 兜底：真走到了登录表单上（判据没拦住），OpenAI 会回这句。它只可能
                # 出现在"已有账号 + 密码不对"的场景，注册流程里等价于该地址已注册。
                if re.search(r"incorrect email address or password|邮箱地址或密码不正确", password_error, re.I):
                    raise _account_exists_failure(email, "提交密码被判 Incorrect email address or password")
                raise _register_failure(f"设置密码失败：{password_error[:200]}")
            password_stage = str(password_result.get("next_stage") or "").strip().lower()
            if password_stage != "otp":
                raise _register_failure(f"设置密码后进入了 {password_stage or 'unknown'} 页，未回到验证码页")

        # 需求步骤 5：轮询取码 → 提交；被判 Incorrect code 时再等一个 codeTimeout
        # 周期收一枚“新的”验证码，两轮都不成就放弃这个账号。
        tried: list[str] = []
        otp_stage = ""
        for attempt in (1, 2):
            if attempt == 2:
                # The provider's own "I need the next code" signal. Best effort:
                # a rejected setStatus just means we keep polling as before.
                if not client.release(mail_id, MAIL_STATUS_NEXT_CODE):
                    logger.warning("[Codex] %s：请求下一封验证码被拒，继续按原节奏轮询", label)
            logger.info(
                "[Codex] %s：等待验证码（第 %d 轮，每 %.0fs 刷新，最长 %.0fs）",
                label,
                attempt,
                code_interval,
                code_timeout,
            )
            code = _wait_for_smsbower_code(
                logger,
                client,
                mail_id,
                timeout=code_timeout,
                interval=code_interval,
                exclude=tried,
                label=label,
                cancel_event=cancel_event,
            )
            if not code:
                raise _register_failure(
                    f"等待验证码超时（第 {attempt} 轮，{int(code_timeout)}s 内没有收到新的验证码）"
                )
            tried.append(code)
            otp_result = _submit_login_step(
                "submit_email_otp", label=label, step="提交邮箱验证码", logger=logger, code=code
            )
            error_text = str(otp_result.get("error_text") or "").strip()
            if not error_text:
                otp_stage = str(otp_result.get("next_stage") or "").strip().lower()
                break
            if attempt == 2:
                raise _register_failure(f"验证码两轮都未通过：{error_text[:200]}")
            logger.warning("[Codex] %s：验证码被拒（%s），继续等待新的验证码", label, error_text[:120])
        if not otp_stage:
            # The submit tore the frame down before the page could answer; the
            # tab's own URL still knows where we ended up.
            otp_stage = _wait_for_register_landing(logger, label)
        logger.info("[Codex] %s：验证码通过，进入阶段：%s", label, otp_stage or "unknown")

        if otp_stage == "about-you":
            full_name, age = _generate_about_you_profile()
            logger.info("[Codex] %s：填写 /about-you（%s / %s 岁）", label, full_name, age)
            notices.push(f"正在填写 about-you（{full_name} / {age} 岁）…", scope="signup")
            about_result = _submit_login_step(
                "submit_about_you",
                label=label,
                step="填写 about-you",
                logger=logger,
                full_name=full_name,
                age=age,
            )
            about_error = str(about_result.get("error_text") or "").strip()
            if about_error:
                raise _register_failure(f"填写 about-you 失败：{about_error[:200]}")

        session = _confirm_logged_in(logger, label=label)
        if session is None:
            raise _register_failure("注册流程走完，但 chatgpt.com 仍未处于登录状态")

        release_status = MAIL_STATUS_FINISH
        # 注册完成后 chatgpt.com 会弹一个原生 <dialog>（"You're all set"），showModal()
        # 会 inert 掉整页。必须先点掉，否则后面探 Plus 资格和开 MFA 的点击全部点空。
        # 它在 load 之后才画出来，所以要**等**：不等的话这里查不到，白白放过去。
        _dismiss_blocking_dialog(logger, label=label, wait_ms=8000)
        # 账号已经建成了，Plus 免费资格只是附加属性：这一步无论成败都不能把
        # 一个注册成功的账号判失败。
        notices.push("正在检查 Plus 免费资格…", scope="signup")
        plus_trial = _probe_plus_trial(logger, label=label)
        store.update_registration(
            email,
            status="registered",
            password=password,
            plus_trial=plus_trial,
            message=(
                "已注册并登录，等待开启 2FA"
                + ("；有 1 个月 Plus 免费资格" if plus_trial else "；无 Plus 免费资格")
            ),
        )
        logger.info(
            "[Codex] %s：%s 注册完成并已登录（Plus 免费资格：%s）",
            label,
            email,
            "有" if plus_trial else "无",
        )

        # 需求步骤 7-9：开启验证器 App，取回 Base32 密钥。
        # 账号此时已经建成、租用的号也已 setStatus=3 结清，所以 MFA 失败**不能**
        # 把整单判失败——那会让一个可用账号显示成"注册失败"。失败就记成"已注册但
        # 未开 2FA"，用户可以事后手动补。
        _raise_if_stopped(cancel_event)
        totp_secret = ""
        mfa_error = ""
        saved_secret = ""
        notices.push("正在开启 2FA（验证器 App）…", scope="mfa")
        try:
            # on_secret：密钥一读到就写库，不等验证码提交的结果。OpenAI 只显示这
            # 一次，押在后续步骤上就等于赌一把——赌输了账号的 2FA 已经开了却没有
            # 密钥，账号直接废掉（真出过一次）。
            def _persist_secret(value: str) -> None:
                nonlocal saved_secret
                saved_secret = value
                store.update_registration(
                    email,
                    status="registered",
                    password=password,
                    totp_secret=value,
                    message="已取得 2FA 密钥（等待验证码提交确认）",
                )

            totp_secret = _run_mfa_enrollment(
                logger,
                label=label,
                password=password,
                on_secret=_persist_secret,
                cancel_event=cancel_event,
            )
        except _RegisterStopped:
            raise
        except Exception as exc:
            mfa_error = str(exc)
            logger.warning("[Codex] %s：开启 2FA 失败（账号本身已注册成功）：%s", label, mfa_error[:240])

        plus_note = "；有 1 个月 Plus 免费资格" if plus_trial else "；无 Plus 免费资格"
        if totp_secret:
            # 密码 + 密钥都齐了：update_registration 会把记录改写成 password_totp，
            # 素材变成 email----密码----密钥（导出时再追加 ----0/1）。
            store.update_registration(
                email,
                status="success",
                password=password,
                totp_secret=totp_secret,
                message="已注册并开启 2FA" + plus_note,
            )
            message = "账号已注册并开启 2FA" + plus_note
        else:
            # 即便验证码那步失败，只要密钥已经拿到就一定要保留：OpenAI 只显示一次，
            # 丢了就再也找不回来（这条是踩过坑之后加的）。
            if saved_secret:
                store.update_registration(
                    email,
                    status="registered",
                    message=f"已取得 2FA 密钥但未确认开启：{mfa_error[:180]}" + plus_note,
                )
                message = f"账号已注册，2FA 密钥已保存但未确认开启：{mfa_error[:100]}" + plus_note
            else:
                store.update_registration(
                    email,
                    status="registered",
                    message=f"已注册但未开启 2FA：{mfa_error[:200]}" + plus_note,
                )
                message = f"账号已注册（2FA 未开启：{mfa_error[:120]}）" + plus_note
        logger.info("[Codex] %s：%s %s", label, email, message)
        return codex_oauth._codex_result(
            status="success",
            ok=True,
            email=email,
            message=message,
        )
    except _RegisterStopped:
        # 用户按了停止：账号没建成，租用的号必须退回（release_status 仍是 CANCEL）。
        # 不当作失败写 register_status=failed，否则清单里会留下一条误导的"注册失败"。
        message = "用户已停止流水线，注册中断"
        store.update_registration(email, status="pending", message=message)
        logger.info("[Codex] %s：%s", label, message)
        return codex_oauth._codex_result(
            status="stopped",
            ok=False,
            email=email,
            message=message,
        )
    except Exception as exc:
        store.update_registration(email, status="failed", message=str(exc)[:300])
        # 这一轮的租用号在下面的 finally 里会被 setStatus=2 退回，**同一个账号再重试
        # 一次必然在取码那步撞 ActivationGone**。所以逃出去的错误必须带上
        # register_failed 令牌，让调度器判成不可重试——否则文案里只要恰好带个"超时"
        # 就会被当成 transient_network 重试，白跑一轮。已有的终局令牌保持原样
        # （它们本来就是不可重试的分类，还各自带着更准确的语义）。
        message = str(exc)
        terminal = (
            _REGISTER_FAILED_TOKEN,
            _ACCOUNT_EXISTS_TOKEN,
            _RISK_BLOCK_TOKEN,
            "account_deactivated",
        )
        if not any(token in message for token in terminal):
            raise _register_failure(message[:300]) from exc
        raise
    finally:
        # Always settle the rental: 3 closes it and pays, 2 hands it back. A
        # provider failure here must not change the account's outcome.
        # **结果一定要写进日志**：租用号一直开着就一直计费，事后翻日志必须能一眼
        # 看出"这个号到底退没退"，而不是靠"代码里有 release"想当然（见下面注释）。
        _settle_rental(logger, client, mail_id, release_status, label=label)


# setStatus 的两个终态，写成中文只为日志好读。
_RENTAL_STATUS_NAMES = {2: "取消并退回", 3: "完成并结清"}


def _settle_rental(logger, client, mail_id: int, status: int, *, label: str = "注册") -> bool:
    """给 smsbower 活动收尾（setStatus），**并把结果如实写进日志**。

    失败不抛异常：账号的成败此刻已经定了，供应商抽风不该把一次成功的注册变成报错。
    但"没退成"必须显式喊出来——号还开着就一直扣钱，只有日志能告诉用户去后台补刀。
    """

    from .smsbower_mail import SmsbowerMailActivationGoneError, SmsbowerMailError

    name = _RENTAL_STATUS_NAMES.get(int(status), str(status))
    try:
        client.set_status(mail_id, status)
    except SmsbowerMailActivationGoneError as exc:
        # 已经取消过/已经结清/id 不存在：这也是"不再计费"，不是问题。
        logger.info(
            "[Codex] %s：smsbower 结算 mail_id=%s setStatus=%s（%s）：该活动已不存在，视为已结清（%s）",
            label,
            mail_id,
            status,
            name,
            str(exc)[:120],
        )
        return True
    except SmsbowerMailError as exc:
        logger.warning(
            "[Codex] %s：smsbower 结算失败 mail_id=%s setStatus=%s（%s）：%s"
            "——该邮箱可能仍在计费，请到 smsbower 后台手动关闭",
            label,
            mail_id,
            status,
            name,
            str(exc)[:160],
        )
        notices.push(
            f"smsbower 邮箱 {mail_id} 未能{name}，可能仍在计费，请到后台确认", level="warn", scope="signup"
        )
        return False
    except Exception as exc:  # noqa: BLE001
        # 它跑在 finally 里：结算自己出问题绝不能盖掉账号的真实结果（成功还是成功，
        # 失败还是那个失败的原因），只如实记一笔。
        logger.warning(
            "[Codex] %s：smsbower 结算调用异常 mail_id=%s setStatus=%s（%s）：%s"
            "——该邮箱可能仍在计费，请到 smsbower 后台手动关闭",
            label,
            mail_id,
            status,
            name,
            f"{type(exc).__name__}: {exc}"[:160],
        )
        return False
    logger.info(
        "[Codex] %s：smsbower 结算成功 mail_id=%s setStatus=%s（%s）", label, mail_id, status, name
    )
    return True


_GCASH_TOKEN_URL = "https://chatgpt.com/api/auth/session"
_GCASH_START_TIMEOUT = 60.0
_GCASH_RUN_TIMEOUT = 1200.0
_GCASH_POLL_SECONDS = 3.0
# Heartbeat cadence for the otherwise-silent 提炼 wait, so the operator can see
# what the 153 page is stuck on instead of staring at a dead log.
_GCASH_PROGRESS_LOG_SECONDS = 15.0
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
    wait_started = time.time()
    start_deadline = wait_started + _GCASH_START_TIMEOUT
    run_deadline = wait_started + _GCASH_RUN_TIMEOUT
    next_progress_log = wait_started + _GCASH_PROGRESS_LOG_SECONDS
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
        # Heartbeat: the loop can otherwise run up to 20 min with no output, so a
        # stuck 提炼 looks like a dead hang. Log the current page state on a timer
        # (probe ok or not) so the operator can see what it is waiting on.
        if now >= next_progress_log:
            next_progress_log = now + _GCASH_PROGRESS_LOG_SECONDS
            waited = int(now - wait_started)
            if probe.get("ok"):
                logger.info(
                    "[gcash] 仍在等待提炼结果（已等 %ds）：percent=%s running=%s stage=%s text=%s result_visible=%s",
                    waited,
                    _gcash_percent(last),
                    bool(last.get("running")),
                    last.get("progress_stage"),
                    last.get("progress_text"),
                    bool(last.get("result_visible")),
                )
            else:
                logger.info(
                    "[gcash] 仍在等待提炼结果（已等 %ds）：探测未就绪（%s），可能页面正在跳转或被节流",
                    waited,
                    str(probe.get("error") or probe.get("tab_url") or "未知")[:160],
                )
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
    _bridge_apply_proxy(mailbox, label="OAuth")
    _bridge_cleanup()
    _bridge_navigate("https://chatgpt.com/login")
    _bridge_navigate(_OPENAI_LOGIN_URL)
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


def _settle_mailbox_rental(settings: Settings, mailbox: dict, *, status: int = 0, reason: str = "", label: str = "注册") -> bool:
    """在 `_run_account_signup` 之外退回一个已租用的邮箱（默认 setStatus=2 取消）。

    `_run_account_signup` 自己的 finally 覆盖了流程内的所有出口；这里管的是**还没
    进到那个函数就失败**的情况（例如浏览器桥没连上）——号已经租下来了，不退就一直
    计费，而且日志里连一行记录都不会有。
    """

    from .smsbower_mail import MAIL_STATUS_CANCEL

    logger = logging.getLogger(__name__)
    try:
        mail_id = int(str(mailbox.get("mail_id") or "").strip())
    except ValueError:
        mail_id = 0
    if mail_id <= 0:
        return False
    if reason:
        logger.info("[Codex] %s：%s，正在退回 smsbower 邮箱 mail_id=%s", label, reason, mail_id)
    try:
        client, _config = _smsbower_mail_runtime(settings)
    except Exception as exc:
        logger.warning(
            "[Codex] %s：smsbower 客户端不可用，mail_id=%s 无法退回，可能仍在计费：%s",
            label,
            mail_id,
            str(exc)[:160],
        )
        return False
    return _settle_rental(logger, client, mail_id, status or MAIL_STATUS_CANCEL, label=label)


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
    # "smsbower-gmail 注册" mode: create the account behind a rented address.
    register_account = bool(mailbox.get("register_account"))
    source = str(mailbox.get("source") or "").strip().lower()
    codex_oauth = _ensure_upstream_imports(settings)

    if register_account:
        # Its own entrypoint: there is no account to log into yet, so none of the
        # OTP providers below apply — the code comes from the mailbox rental.
        if not _browser_flow_available():
            # 一步都没用上这个号：立刻退回，否则它会一直计费而日志里连一行都没有。
            _settle_mailbox_rental(settings, mailbox, reason="浏览器桥未连接，注册无法开始")
            raise _register_failure("注册需要浏览器桥（要在活动页完成建号），当前未连接")
        logging.getLogger(__name__).info(
            "[Codex] 浏览器桥已连接，进入 smsbower-gmail 注册模式（不接码短信/不走 OAuth）"
        )
        return _run_account_signup(settings, mailbox, cancel_event=cancel_event)

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
