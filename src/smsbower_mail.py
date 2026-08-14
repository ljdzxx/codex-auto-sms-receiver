from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import requests


SMSBOWER_MAIL_API_BASE = "https://smsbower.page/api/mail"

# setStatus values, straight from the smsbower mail API doc.
MAIL_STATUS_CANCEL = 2
MAIL_STATUS_FINISH = 3
MAIL_STATUS_NEXT_CODE = 5

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OTP_RE = re.compile(r"\d{4,8}")


class SmsbowerMailError(RuntimeError):
    """Any smsbower mail API failure, already stripped of the api_key."""


class SmsbowerMailOutOfStockError(SmsbowerMailError):
    """The provider has no mailbox of the requested service/domain right now."""


class SmsbowerMailCodePendingError(SmsbowerMailError):
    """The activation exists but no verification code has arrived yet."""


class SmsbowerMailActivationGoneError(SmsbowerMailError):
    """The activation id is unknown or has already been cancelled."""


@dataclass(frozen=True)
class MailActivation:
    """One rented mailbox: the address to register with and its activation id."""

    email: str
    mail_id: int


def _repair_json(text: str) -> str:
    """Best-effort fix for the shapes smsbower's own docs show.

    Their examples are not valid JSON (``{"status":1"mail":"x","mailId":4,}`` —
    a missing comma and a trailing one), so a strict parse of a live response
    that looks like the docs would fail. Repair the two documented defects
    instead of guessing at the payload with a regex.
    """

    # Drop the trailing comma before a closing brace/bracket, then insert the
    # comma the docs omit between a value and the key that follows it.
    repaired = re.sub(r",\s*([}\]])", r"\1", text)
    return re.sub(r'([0-9"])\s*(")(?=[A-Za-z_])', r"\1,\2", repaired)


def _extract_fields(text: str) -> dict[str, Any]:
    """Last resort: pull the documented fields out of an unparsable body."""

    values: dict[str, Any] = {}
    for key in ("mail", "code", "error", "message"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]*)"', text)
        if match:
            values[key] = match.group(1)
    for key in ("status", "mailId"):
        match = re.search(rf'"{key}"\s*:\s*"?(-?\d+)"?', text)
        if match:
            values[key] = int(match.group(1))
    return values


def _parse_payload(text: str) -> dict[str, Any]:
    body = str(text or "").strip()
    if not body:
        return {}
    for candidate in (body, _repair_json(body)):
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return _extract_fields(body)


def _error_text(payload: Mapping[str, Any]) -> str:
    """The provider's failure text. Only meaningful when ``status`` is not 1 —
    a successful setStatus answers ``{"status":1,"message":"Success"}``."""

    for key in ("error", "msg", "message"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return ""


def _classify(message: str) -> type[SmsbowerMailError]:
    lowered = message.casefold()
    if "no mails" in lowered or "no mail yet" in lowered:
        return SmsbowerMailOutOfStockError
    if "has not been received" in lowered or "try again later" in lowered:
        return SmsbowerMailCodePendingError
    if "pass mail id" in lowered or "no activation found" in lowered or "already canceled" in lowered:
        return SmsbowerMailActivationGoneError
    return SmsbowerMailError


class SmsbowerMailClient:
    """Backend-only client for smsbower's rented-mailbox API.

    Errors never carry the request URL: it holds ``api_key`` in the query
    string, and most HTTP libraries put the full URL in their exception text.
    """

    def __init__(
        self,
        api_key: str,
        *,
        http_get: Callable[..., Any] | None = None,
        timeout_seconds: int = 20,
        api_base: str = SMSBOWER_MAIL_API_BASE,
    ) -> None:
        self._api_key = str(api_key or "").strip()
        self._http_get = http_get or requests.get
        self._timeout_seconds = max(3, min(60, int(timeout_seconds)))
        self._api_base = (str(api_base or "").strip() or SMSBOWER_MAIL_API_BASE).rstrip("/")

    def _request(self, endpoint: str, **params: Any) -> dict[str, Any]:
        if not self._api_key:
            raise SmsbowerMailError("smsbower 邮箱 API Key 尚未配置")
        query = {"api_key": self._api_key}
        query.update({key: value for key, value in params.items() if value not in (None, "")})
        try:
            response = self._http_get(
                f"{self._api_base}/{endpoint}",
                params=query,
                headers={"User-Agent": "codex-auto-sms-receiver/1.0", "Accept": "application/json,text/plain"},
                timeout=self._timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - see docstring: never echo the URL
            raise SmsbowerMailError(f"smsbower 邮箱接口网络请求失败（{type(exc).__name__}）") from exc

        status_code = int(getattr(response, "status_code", 0) or 0)
        payload = _parse_payload(getattr(response, "text", "") or "")
        if str(payload.get("status", "")).strip() in {"1", "true", "True"}:
            return payload
        message = _error_text(payload)
        if message:
            raise _classify(message)(f"smsbower 邮箱接口：{message}")
        if status_code and status_code != 200:
            raise SmsbowerMailError(f"smsbower 邮箱接口 HTTP {status_code}")
        raise SmsbowerMailError("smsbower 邮箱接口返回了无法识别的响应")

    def acquire(
        self,
        *,
        service: str = "dr",
        domain: str = "gmail.com",
        max_price: str = "",
        ref: str = "",
        alias: str = "",
    ) -> MailActivation:
        payload = self._request(
            "getActivation",
            service=service,
            domain=domain,
            maxPrice=max_price,
            ref=ref,
            alias=alias,
        )
        email = str(payload.get("mail") or "").strip()
        if not _EMAIL_RE.match(email):
            raise SmsbowerMailError("smsbower 邮箱接口没有返回有效邮箱地址")
        try:
            mail_id = int(str(payload.get("mailId") or payload.get("id") or "").strip())
        except ValueError as exc:
            raise SmsbowerMailError("smsbower 邮箱接口没有返回有效的 mailId") from exc
        if mail_id <= 0:
            raise SmsbowerMailError("smsbower 邮箱接口没有返回有效的 mailId")
        return MailActivation(email=email, mail_id=mail_id)

    def fetch_code(self, mail_id: int | str) -> str:
        """Return the 4-8 digit code, or raise ``SmsbowerMailCodePendingError``."""

        payload = self._request("getCode", mailId=str(mail_id).strip())
        raw = str(payload.get("code") or "").strip()
        if not raw:
            raise SmsbowerMailCodePendingError("smsbower 邮箱接口：验证码尚未到达")
        match = _OTP_RE.search(raw)
        if not match:
            raise SmsbowerMailError("smsbower 邮箱接口返回的验证码格式无法识别")
        return match.group(0)

    def set_status(self, mail_id: int | str, status: int) -> None:
        self._request("setStatus", id=str(mail_id).strip(), status=int(status))

    def release(self, mail_id: int | str, status: int) -> bool:
        """Cancel/finish an activation without ever failing the caller.

        Both endings are bookkeeping: the account outcome is already decided, so
        a provider hiccup here must not turn a finished run into an error. The
        caller logs the returned flag instead.
        """

        try:
            self.set_status(mail_id, status)
        except SmsbowerMailError:
            return False
        return True


__all__ = [
    "MAIL_STATUS_CANCEL",
    "MAIL_STATUS_FINISH",
    "MAIL_STATUS_NEXT_CODE",
    "MailActivation",
    "SMSBOWER_MAIL_API_BASE",
    "SmsbowerMailActivationGoneError",
    "SmsbowerMailClient",
    "SmsbowerMailCodePendingError",
    "SmsbowerMailError",
    "SmsbowerMailOutOfStockError",
]
