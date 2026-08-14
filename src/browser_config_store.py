from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

# Browser-side waiting budgets, in milliseconds. Defaults match the values that
# used to be hardcoded in background.js so an unconfigured install behaves
# exactly as before.
_DEFAULTS: dict[str, int] = {
    # chrome.tabs navigation → "标签页加载超时"
    "page_load_timeout_ms": 45_000,
    # waitFor() inside the injected page step → "未找到邮箱输入框" and friends
    "element_wait_timeout_ms": 30_000,
}
_BOUNDS: dict[str, tuple[int, int]] = {
    "page_load_timeout_ms": (10_000, 300_000),
    "element_wait_timeout_ms": (5_000, 300_000),
}
_LABELS = {
    "page_load_timeout_ms": "页面加载超时",
    "element_wait_timeout_ms": "页面元素等待超时",
}
# The Python side must always outlive the browser side, otherwise both ends time
# out at once and the job is left orphaned (see CLAUDE.md 踩坑 #2). These margins
# derive the backend budgets from whatever the user configures, so the invariant
# cannot be broken by editing one number in the UI.
_NAVIGATE_MARGIN_MS = 45_000
_PAGE_ACTION_MARGIN_MS = 60_000
# submit_email can burn the element budget up to three times in one call
# (login-link click → email box → post-submit settle) before returning.
_PAGE_ACTION_WAIT_MULTIPLIER = 3
_CACHE_SECONDS = 5.0

# ------------------------------------------------------------------ 浏览器指纹
# What the browser reports as its timezone / language, pinned by the operator
# instead of derived from the proxy's exit country. Stored here so the value is
# inspectable next to the rest of the local state; the extension keeps its own
# copy in chrome.storage.local (it has to keep applying the overrides while the
# side panel is closed) and the side panel pushes this one down whenever the
# 调试 page opens or the form is saved.
_FINGERPRINT_KEY = "fingerprint"
_FINGERPRINT_DEFAULT: dict[str, Any] = {"enabled": False, "timezone": "", "language": ""}
# IANA zone names: "UTC", "Asia/Shanghai", "America/Argentina/Buenos_Aires".
_TIMEZONE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+.-]+){0,2}$")
# BCP-47 language tags: "en", "zh-CN", "sr-Latn-RS".
_LANGUAGE_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")


def _known_timezones() -> set[str] | None:
    """Every IANA zone this machine knows, or None when it knows none.

    zoneinfo needs either system tz data or the `tzdata` package; on a bare
    Windows install it has neither, and refusing every timezone in that case
    would be worse than accepting a well-formed name we cannot verify.
    """
    try:
        from zoneinfo import available_timezones

        zones = available_timezones()
    except Exception:
        return None
    return zones or None


def _validate_fingerprint(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("指纹配置必须是 JSON 对象")
    timezone = str(payload.get("timezone") or "").strip()
    language = str(payload.get("language") or "").strip()
    enabled = bool(payload.get("enabled"))
    if timezone:
        if not _TIMEZONE_RE.match(timezone):
            raise ValueError(f"时区格式不正确：{timezone}（应为 IANA 名称，如 Asia/Shanghai）")
        zones = _known_timezones()
        if zones is not None and timezone not in zones:
            raise ValueError(f"未知时区：{timezone}")
    if language and not _LANGUAGE_RE.match(language):
        raise ValueError(f"语言标签格式不正确：{language}（应为 BCP-47，如 zh-CN）")
    if enabled and not (timezone and language):
        # Enabling with a blank field would override with nothing at all, and
        # guessing a value here is worse than leaving the browser untouched.
        raise ValueError("启用指纹前必须同时填写时区和语言")
    return {"enabled": enabled, "timezone": timezone, "language": language}


def _coerce_fingerprint(payload: Any) -> dict[str, Any]:
    """Same shape, but for reads: a corrupt file must not break the page."""
    try:
        return _validate_fingerprint(payload)
    except ValueError:
        return dict(_FINGERPRINT_DEFAULT)


class BrowserConfigStore:
    """Tunables for how long browser-side steps may wait.

    Lives next to the other local state as JSON. Worker threads read it on every
    bridge request, so reads are cached for a few seconds — long enough to avoid
    hammering the disk, short enough that a change in the UI applies to the next
    account without restarting anything.
    """

    FILENAME = "browser-config.json"

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / self.FILENAME
        self._lock = threading.RLock()
        self._cache: dict[str, int] | None = None
        self._cache_at = 0.0

    @staticmethod
    def _clamp(key: str, value: Any) -> int:
        low, high = _BOUNDS[key]
        try:
            number = int(float(value))
        except (TypeError, ValueError):
            return _DEFAULTS[key]
        return max(low, min(high, number))

    def _read_raw(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        return payload if isinstance(payload, dict) else {}

    def _read(self) -> dict[str, int]:
        payload = self._read_raw()
        return {key: self._clamp(key, payload.get(key, default)) for key, default in _DEFAULTS.items()}

    def get(self) -> dict[str, int]:
        now = time.time()
        with self._lock:
            if self._cache is not None and (now - self._cache_at) < _CACHE_SECONDS:
                return dict(self._cache)
            values = self._read()
            self._cache = values
            self._cache_at = now
        return dict(values)

    def fingerprint(self) -> dict[str, Any]:
        return _coerce_fingerprint(self._read_raw().get(_FINGERPRINT_KEY))

    def save(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("请提交 JSON 对象")
        stored = self._read_raw()
        current = self._read()
        values: dict[str, Any] = {}
        for key, default in _DEFAULTS.items():
            if key not in payload or payload[key] in (None, ""):
                values[key] = current.get(key, default)
                continue
            try:
                number = int(float(payload[key]))
            except (TypeError, ValueError):
                raise ValueError(f"{_LABELS[key]}必须是数字") from None
            low, high = _BOUNDS[key]
            if not low <= number <= high:
                raise ValueError(f"{_LABELS[key]}必须在 {low // 1000} - {high // 1000} 秒之间")
            values[key] = number
        # Validated before anything is written, so a rejected fingerprint leaves
        # the timeouts (and the file) untouched.
        fingerprint = (
            _validate_fingerprint(payload[_FINGERPRINT_KEY])
            if _FINGERPRINT_KEY in payload and payload[_FINGERPRINT_KEY] is not None
            else _coerce_fingerprint(stored.get(_FINGERPRINT_KEY))
        )
        values[_FINGERPRINT_KEY] = fingerprint
        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            temporary = self.data_dir / f".{self.FILENAME}.tmp"
            temporary.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(self.path)
            self._cache = {key: values[key] for key in _DEFAULTS}
            self._cache_at = time.time()
        return dict(values)

    def public(self) -> dict[str, Any]:
        values = self.get()
        return {
            **values,
            "defaults": dict(_DEFAULTS),
            "bounds": {key: {"min": low, "max": high} for key, (low, high) in _BOUNDS.items()},
            "fingerprint": self.fingerprint(),
            # Shown in the UI so it is obvious that the backend always waits
            # longer than the browser it is driving.
            "derived": {
                "navigate_bridge_timeout_ms": navigate_bridge_timeout_ms(values),
                "page_action_bridge_timeout_ms": page_action_bridge_timeout_ms(values),
            },
        }


def navigate_bridge_timeout_ms(values: dict[str, int]) -> int:
    return int(values.get("page_load_timeout_ms", _DEFAULTS["page_load_timeout_ms"])) + _NAVIGATE_MARGIN_MS


def page_action_bridge_timeout_ms(values: dict[str, int]) -> int:
    budget = int(values.get("element_wait_timeout_ms", _DEFAULTS["element_wait_timeout_ms"]))
    return budget * _PAGE_ACTION_WAIT_MULTIPLIER + _PAGE_ACTION_MARGIN_MS


__all__ = [
    "BrowserConfigStore",
    "navigate_bridge_timeout_ms",
    "page_action_bridge_timeout_ms",
]
