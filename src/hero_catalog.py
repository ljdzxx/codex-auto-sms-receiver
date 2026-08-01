from __future__ import annotations

import copy
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

import requests

from .hero_pricing import HERO_SMS_API_BASE


_POPULAR_IDS = (187, 16, 52, 3, 10, 6, 7, 4, 22, 36, 43, 78, 73, 54, 182, 175, 196)
_POPULAR_ORDER = {country_id: index for index, country_id in enumerate(_POPULAR_IDS)}
_CHINESE_NAME_OVERRIDES = {
    16: "英国",
    78: "法国",
    175: "澳大利亚",
    187: "美国（实体号码）",
    196: "新加坡",
}
_FLAGS = {
    1: "🇺🇦",
    3: "🇨🇳",
    4: "🇵🇭",
    6: "🇮🇩",
    7: "🇲🇾",
    10: "🇻🇳",
    15: "🇵🇱",
    16: "🇬🇧",
    22: "🇮🇳",
    36: "🇨🇦",
    43: "🇩🇪",
    52: "🇹🇭",
    54: "🇲🇽",
    73: "🇧🇷",
    78: "🇫🇷",
    175: "🇦🇺",
    182: "🇯🇵",
    187: "🇺🇸",
    196: "🇸🇬",
}

# The live public directory is preferred. This small verified snapshot keeps
# the selector readable when Hero SMS is temporarily unreachable.
_FALLBACK_COUNTRIES = (
    (187, "美国（实体号码）", "USA"),
    (16, "英国", "United Kingdom"),
    (52, "泰国", "Thailand"),
    (3, "中国", "China"),
    (10, "越南", "Vietnam"),
    (6, "印度尼西亚", "Indonesia"),
    (7, "马来西亚", "Malaysia"),
    (4, "菲律宾", "Philippines"),
    (22, "印度", "India"),
    (36, "加拿大", "Canada"),
    (43, "德国", "Germany"),
    (78, "法国", "France"),
    (73, "巴西", "Brazil"),
    (54, "墨西哥", "Mexico"),
    (182, "日本", "Japan"),
    (175, "澳大利亚", "Australia"),
    (196, "新加坡", "Singapore"),
    (1, "乌克兰", "Ukraine"),
    (15, "波兰", "Poland"),
)


def _country_row(country_id: int, chinese: str, english: str) -> dict[str, Any]:
    chinese = _CHINESE_NAME_OVERRIDES.get(country_id, chinese).strip()
    english = english.strip()
    return {
        "id": str(country_id),
        "name": chinese or english or f"国家 {country_id}",
        "name_en": english,
        "flag": _FLAGS.get(country_id, "🌐"),
        "popular": country_id in _POPULAR_ORDER,
    }


def _normalize_countries(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, Mapping):
        items = payload.values()
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError("Hero SMS 国家目录格式不正确")

    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("visible", "1")).strip().lower() in {"0", "false", "no"}:
            continue
        try:
            country_id = int(str(item.get("id") or "").strip())
        except ValueError:
            continue
        if country_id < 0 or country_id in seen:
            continue
        seen.add(country_id)
        chinese = str(item.get("chn") or item.get("chi") or item.get("name") or "")
        english = str(item.get("eng") or item.get("nameEn") or item.get("name_en") or "")
        rows.append(_country_row(country_id, chinese, english))

    if not rows:
        raise ValueError("Hero SMS 国家目录为空")
    rows.sort(
        key=lambda row: (
            0 if row["popular"] else 1,
            _POPULAR_ORDER.get(int(row["id"]), 9999),
            row["name"].casefold(),
            int(row["id"]),
        )
    )
    return rows


class HeroCatalog:
    """Cached, keyless Hero SMS country directory for the local WebUI."""

    def __init__(
        self,
        *,
        http_get: Callable[..., Any] | None = None,
        ttl_seconds: int = 3600,
        fallback_ttl_seconds: int = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http_get = http_get or requests.get
        self._ttl_seconds = max(60, int(ttl_seconds))
        self._fallback_ttl_seconds = max(30, int(fallback_ttl_seconds))
        self._clock = clock
        self._lock = threading.RLock()
        self._cached: dict[str, Any] | None = None
        self._expires_at = 0.0

    def catalog(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            if self._cached is not None and now < self._expires_at:
                return copy.deepcopy(self._cached)

        try:
            response = self._http_get(
                HERO_SMS_API_BASE,
                params={"action": "getCountries", "lang": "cn"},
                headers={"User-Agent": "codex-auto-sms-receiver/1.0"},
                timeout=15,
            )
            if int(getattr(response, "status_code", 0) or 0) != 200:
                raise RuntimeError("Hero SMS 国家目录请求失败")
            payload = response.json()
            countries = _normalize_countries(payload)
            source = "live"
            ttl = self._ttl_seconds
        except Exception:
            countries = [_country_row(*item) for item in _FALLBACK_COUNTRIES]
            source = "fallback"
            ttl = self._fallback_ttl_seconds

        result = {
            "countries": countries,
            "source": source,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "service": {"code": "dr", "name": "OpenAI"},
        }
        with self._lock:
            self._cached = result
            self._expires_at = now + ttl
        return copy.deepcopy(result)


__all__ = ["HeroCatalog", "_normalize_countries"]
