from __future__ import annotations

import json
import re
import secrets
import threading
from pathlib import Path
from typing import Any


# smsbower's mail API only sells one service/domain combination that matters
# here (`dr` = OpenAI on gmail.com), so those stay fixed instead of becoming two
# more fields the operator can get wrong.
MAIL_SERVICE = "dr"
MAIL_DOMAIN = "gmail.com"

_DEFAULTS: dict[str, Any] = {
    "api_key": "",
    # Blank = 不限价, which is what the API does when maxPrice is omitted.
    "max_price": "",
    "code_timeout_seconds": 120,
    "code_interval_seconds": 5,
    # 取号失败（多半是 "No mails yet" 库存空）等多久重试。取号失败**不中断**
    # 流水线：号是一个一个租的，中途断掉等于把整批剩下的计划都丢了。
    "supply_retry_seconds": 10,
    # 前一个账号产生终态结果后，等多久再首次领取下一个账号。
    "next_account_interval_seconds": 60,
}
_BOUNDS: dict[str, tuple[int, int]] = {
    "code_timeout_seconds": (30, 900),
    "code_interval_seconds": (2, 60),
    "supply_retry_seconds": (5, 600),
    "next_account_interval_seconds": (0, 3600),
}
_LABELS = {
    "code_timeout_seconds": "验证码超时",
    "code_interval_seconds": "验证码刷新频率",
    "supply_retry_seconds": "取号失败重试间隔",
    "next_account_interval_seconds": "处理下一个账号间隔",
}
_PRICE_RE = re.compile(r"^\d+(\.\d{1,4})?$")


def mask_api_key(value: str) -> str:
    """Show enough of the key to recognise it, never enough to reuse it."""

    key = str(value or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * max(4, len(key) - 8)}{key[-4:]}"


def _validate_price(value: Any) -> str:
    price = str(value if value is not None else "").strip()
    if not price:
        return ""
    if not _PRICE_RE.match(price):
        raise ValueError("邮箱价格上限必须是非负数字，例如 0.5")
    if float(price) <= 0:
        raise ValueError("邮箱价格上限必须大于 0，留空表示不限价")
    return price


class SmsbowerMailConfigStore:
    """Persisted settings for the smsbower-gmail 登录素材类型.

    Kept in its own file next to the other local state. The api_key is written
    in full (the backend has to send it to smsbower) but only ever leaves this
    process masked — see :meth:`public`.
    """

    FILENAME = "smsbower-mail.json"

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / self.FILENAME
        self._lock = threading.RLock()

    def _read_raw(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _clamp(key: str, value: Any) -> int:
        low, high = _BOUNDS[key]
        try:
            number = int(float(value))
        except (TypeError, ValueError):
            return int(_DEFAULTS[key])
        return max(low, min(high, number))

    def get(self) -> dict[str, Any]:
        """Full settings, api_key included — backend use only."""

        stored = self._read_raw()
        values: dict[str, Any] = {
            "api_key": str(stored.get("api_key") or "").strip(),
            "max_price": str(stored.get("max_price") or "").strip(),
        }
        for key in _BOUNDS:
            values[key] = self._clamp(key, stored.get(key, _DEFAULTS[key]))
        return values

    def public(self) -> dict[str, Any]:
        values = self.get()
        api_key = values.pop("api_key", "")
        return {
            **values,
            "api_key_masked": mask_api_key(api_key),
            "api_key_configured": bool(api_key),
            "service": MAIL_SERVICE,
            "domain": MAIL_DOMAIN,
            "defaults": {key: _DEFAULTS[key] for key in _BOUNDS},
            "bounds": {key: {"min": low, "max": high} for key, (low, high) in _BOUNDS.items()},
        }

    def save(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("请提交 JSON 对象")
        current = self.get()
        values: dict[str, Any] = {}

        # A blank api_key means "keep the saved one": the UI only ever shows the
        # masked value, so re-submitting the form must not wipe the real key.
        api_key = str(payload.get("api_key") or "").strip()
        if not api_key:
            api_key = current["api_key"]
        elif any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in api_key):
            raise ValueError("API Key 包含无效字符")
        elif len(api_key) > 256:
            raise ValueError("API Key 长度超出限制")
        if not api_key:
            raise ValueError("请填写 smsbower 邮箱 API Key")
        values["api_key"] = api_key

        values["max_price"] = (
            _validate_price(payload.get("max_price"))
            if "max_price" in payload
            else current["max_price"]
        )

        for key in _BOUNDS:
            if key not in payload or payload[key] in (None, ""):
                values[key] = current[key]
                continue
            try:
                number = int(float(payload[key]))
            except (TypeError, ValueError):
                raise ValueError(f"{_LABELS[key]}必须是数字") from None
            low, high = _BOUNDS[key]
            if not low <= number <= high:
                raise ValueError(f"{_LABELS[key]}必须在 {low} - {high} 秒之间")
            values[key] = number
        if values["code_interval_seconds"] >= values["code_timeout_seconds"]:
            raise ValueError("验证码刷新频率必须小于验证码超时时间")

        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            temporary = self.data_dir / f".{self.FILENAME}.{secrets.token_hex(8)}.tmp"
            temporary.write_text(json.dumps(values, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.path)
        return self.public()


__all__ = ["MAIL_DOMAIN", "MAIL_SERVICE", "SmsbowerMailConfigStore", "mask_api_key"]
