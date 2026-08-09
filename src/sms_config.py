from __future__ import annotations

import json
import os
import re
import secrets
import threading
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterable, Mapping

from dotenv import dotenv_values


_ENV_LINE = re.compile(r"^(?P<prefix>\s*(?:export\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=.*$")
_PRICE_VALUE = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d{1,4})?$")

# These settings belonged to providers that are intentionally unsupported by
# this login-only project. Saving the Hero configuration also removes stale
# copies from the local .env so they cannot silently become active again.
_REMOVED_PROVIDER_KEYS = {
    "SMS_PROVIDER_ORDER",
    "SMS_API_KEY",
    "L_API_BASE",
    "L_ADMIN_AUTH_CODE",
    "L_PHONE_PREFIX",
    "H_API_BASE",
    "H_ADMIN_AUTH_CODE",
    "H_PHONE_PREFIX",
    "H_PHONE_ACQUIRE_MODE",
}


def _single_line(value: object, *, field: str, max_length: int = 4096) -> str:
    text = "" if value is None else str(value).strip()
    if len(text) > max_length:
        raise ValueError(f"{field}过长")
    if any(ord(char) < 32 for char in text):
        raise ValueError(f"{field}不能包含控制字符")
    return text


def _integer(value: object, *, field: str, minimum: int, maximum: int) -> str:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}必须是整数") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field}必须在 {minimum} - {maximum} 之间")
    return str(parsed)


def _env_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _stored_integer(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _boolean(value: object, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{field}必须是布尔值")


def _stored_boolean(value: str, default: bool = False) -> bool:
    try:
        return _boolean(value, field="布尔配置")
    except ValueError:
        return default


def _sequence(value: object) -> list[object]:
    if isinstance(value, (list, tuple)):
        return list(value)
    if value is None:
        return []
    return [item for item in re.split(r"[,\s;，；]+", str(value).strip()) if item]


def normalize_hero_countries(value: object, *, fallback: Iterable[object] = ()) -> list[str]:
    source = _sequence(value) or list(fallback)
    result: list[str] = []
    for item in source:
        if isinstance(item, Mapping):
            item = item.get("id", item.get("country", item.get("value", "")))
        text = _single_line(item, field="Hero SMS 国家 ID", max_length=12)
        if not text or not text.isdigit():
            raise ValueError("Hero SMS 国家 ID 必须是数字")
        country_id = int(text)
        if country_id < 0 or country_id > 9999:
            raise ValueError("Hero SMS 国家 ID 必须在 0 - 9999 之间")
        normalized = str(country_id)
        if normalized not in result:
            result.append(normalized)
        if len(result) > 10:
            raise ValueError("Hero SMS 国家最多选择 10 个")
    return result


def normalize_channel_priority(value: object, *, allowed: Iterable[str]) -> list[str]:
    """Return an ordered, de-duplicated list of enabled channel ids.

    The order *is* the priority: earlier channels are tried first when more
    than one channel can supply a number for a country.
    """

    allowed_set = {str(item).strip().lower() for item in allowed}
    result: list[str] = []
    for item in _sequence(value):
        name = _single_line(item, field="接码渠道", max_length=32).lower()
        if not name:
            continue
        if name not in allowed_set:
            raise ValueError(f"不支持的接码渠道：{name}")
        if name not in result:
            result.append(name)
    return result


def normalize_price(value: object, *, field: str) -> str:
    text = _single_line(value, field=field, max_length=32)
    if not text:
        return ""
    if not _PRICE_VALUE.fullmatch(text):
        raise ValueError(f"{field}必须是正数，且最多 4 位小数")
    try:
        parsed = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError(f"{field}格式不正确") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError(f"{field}必须是正数，且最多 4 位小数")
    return format(parsed.quantize(Decimal("0.0001")).normalize(), "f")


def _country_prices_from_env(raw: object) -> dict[str, dict]:
    """Parse a stored per-country price map (JSON) into a plain dict.

    Shape: ``{"<countryId>": {"max": "0.10", "fixed": true}}`` for Hero and
    ``{"<countryId>": {"min": "0.05", "max": "0.20"}}`` for smsbower. Malformed
    entries are dropped rather than raising — the caller falls back gracefully.
    """
    if isinstance(raw, Mapping):
        data = dict(raw)
    else:
        text = str(raw or "").strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            return {}
    if not isinstance(data, dict):
        return {}
    result: dict[str, dict] = {}
    for key, entry in data.items():
        country = str(key).strip()
        if not country.isdigit() or not isinstance(entry, Mapping):
            continue
        result[str(int(country))] = dict(entry)
    return result


def normalize_country_prices(
    raw: object,
    countries: Iterable[str],
    *,
    channel: str,
) -> dict[str, dict]:
    """Validate and normalize per-country prices for the selected countries.

    Every selected country MUST carry a max price (per the "每国必填" rule).
    Hero entries keep ``{max, fixed}`` (fixed defaults to False); smsbower keeps
    ``{min?, max}`` with an optional lower bound that must not exceed max.
    Returns a clean map keyed by country id, restricted to ``countries``.
    """
    source = _country_prices_from_env(raw)
    wanted = [str(c) for c in countries]
    result: dict[str, dict] = {}
    for country in wanted:
        entry = source.get(country) or {}
        max_price = normalize_price(entry.get("max"), field=f"国家 {country} 价格上限")
        if not max_price:
            raise ValueError(f"国家 {country} 必须设置单号价格上限（maxPrice）")
        if channel == "hero":
            fixed = _boolean(entry.get("fixed", False), field=f"国家 {country} 精准价格")
            result[country] = {"max": max_price, "fixed": bool(fixed)}
        else:
            min_price = normalize_price(entry.get("min"), field=f"国家 {country} 最低购买价")
            if min_price and Decimal(min_price) > Decimal(max_price):
                raise ValueError(f"国家 {country} 的最低购买价不能高于价格上限")
            result[country] = {"max": max_price}
            if min_price:
                result[country]["min"] = min_price
    return result


def _validate_price_range(min_price: str, max_price: str, preferred_price: str) -> None:
    minimum = Decimal(min_price) if min_price else None
    maximum = Decimal(max_price) if max_price else None
    preferred = Decimal(preferred_price) if preferred_price else None
    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError("最低购买价不能高于价格上限")
    if preferred is not None and minimum is not None and preferred < minimum:
        raise ValueError("指定价格档位不能低于最低购买价")
    if preferred is not None and maximum is not None and preferred > maximum:
        raise ValueError("指定价格档位不能高于价格上限")


class SmsConfigStore:
    """Persist the Hero SMS configuration without exposing its API key."""

    _KEYS = {
        # Upstream compatibility fields. They are always written as Hero/dr;
        # the upstream SMS lifecycle module stays Hero-anchored while smsbower
        # is layered on as an additional in-coordinator channel.
        "SMS_PROVIDER",
        "SMS_COUNTRY",
        "SMS_SERVICE",
        "SMS_MAX_PRICE",
        "SMS_MAX_RETRIES",
        # Global fallback for the SMS-code wait. Per-channel overrides
        # (HERO_SMS_CODE_WAIT / SMSBOWER_CODE_WAIT) take precedence when set.
        "SMS_CODE_WAIT",
        # Ordered, comma-separated list of enabled receiving channels. The
        # order is the channel priority used when several channels can serve a
        # number (mirrors the per-country priority within a channel).
        "SMS_CHANNEL_PRIORITY",
        # Hero-owned settings.
        "HERO_SMS_API_KEY",
        "HERO_SMS_COUNTRIES",
        "HERO_SMS_MIN_PRICE",
        "HERO_SMS_MAX_PRICE",
        "HERO_SMS_PREFERRED_PRICE",
        # Per-country price map (JSON): {"<id>": {"max": "0.10", "fixed": bool}}.
        # Supersedes the channel-wide HERO_SMS_MAX_PRICE for acquisition.
        "HERO_SMS_COUNTRY_PRICES",
        "HERO_SMS_ACQUIRE_PRIORITY",
        "HERO_SMS_REUSE_ENABLED",
        "HERO_SMS_CODE_WAIT",
        # smsbower-owned settings (parallel to the Hero block).
        "SMSBOWER_API_KEY",
        "SMSBOWER_COUNTRIES",
        "SMSBOWER_MIN_PRICE",
        "SMSBOWER_MAX_PRICE",
        "SMSBOWER_PREFERRED_PRICE",
        # Per-country price map (JSON): {"<id>": {"min"?: "0.05", "max": "0.20"}}.
        "SMSBOWER_COUNTRY_PRICES",
        "SMSBOWER_ACQUIRE_PRIORITY",
        "SMSBOWER_CODE_WAIT",
    }

    # Provider ids that may appear in SMS_CHANNEL_PRIORITY / payload.
    _CHANNELS = ("hero", "smsbower")

    def __init__(self, env_path: Path):
        self.env_path = Path(env_path)
        self._lock = threading.RLock()

    def _values(self) -> dict[str, str]:
        persisted = dotenv_values(self.env_path) if self.env_path.is_file() else {}
        return {
            key: str(os.getenv(key, persisted.get(key) or "") or "")
            for key in self._KEYS
        }

    def snapshot(self) -> dict:
        with self._lock:
            values = self._values()

        legacy_country = values["SMS_COUNTRY"].strip()
        fallback = (legacy_country,) if legacy_country.isdigit() else ()
        try:
            countries = normalize_hero_countries(
                values["HERO_SMS_COUNTRIES"],
                fallback=fallback,
            )
        except ValueError:
            countries = list(fallback)

        def stored_price(name: str, *, legacy: str = "", label: str) -> str:
            try:
                return normalize_price(values[name] or (values[legacy] if legacy else ""), field=label)
            except ValueError:
                return ""

        min_price = stored_price("HERO_SMS_MIN_PRICE", label="最低购买价")
        max_price = (
            stored_price("HERO_SMS_MAX_PRICE", legacy="SMS_MAX_PRICE", label="价格上限")
            or "0.11"
        )
        preferred_price = stored_price("HERO_SMS_PREFERRED_PRICE", label="指定价格档位")
        acquire_priority = values["HERO_SMS_ACQUIRE_PRIORITY"].strip().lower()
        if acquire_priority not in {"country", "price", "price_high"}:
            acquire_priority = "country"
        configured = bool(values["HERO_SMS_API_KEY"].strip())

        # smsbower channel snapshot (parallel to Hero, no legacy fallbacks).
        try:
            smsbower_countries = normalize_hero_countries(values["SMSBOWER_COUNTRIES"])
        except ValueError:
            smsbower_countries = []
        smsbower_min = stored_price("SMSBOWER_MIN_PRICE", label="最低购买价")
        smsbower_max = stored_price("SMSBOWER_MAX_PRICE", label="价格上限")
        smsbower_preferred = stored_price("SMSBOWER_PREFERRED_PRICE", label="指定价格档位")
        smsbower_priority = values["SMSBOWER_ACQUIRE_PRIORITY"].strip().lower()
        if smsbower_priority not in {"country", "price", "price_high"}:
            smsbower_priority = "country"
        smsbower_configured = bool(values["SMSBOWER_API_KEY"].strip())

        # Per-channel SMS-code wait. Each channel falls back to the global
        # SMS_CODE_WAIT, which itself defaults to 30s.
        global_code_wait = _stored_integer(values["SMS_CODE_WAIT"], 30)
        hero_code_wait = _stored_integer(values["HERO_SMS_CODE_WAIT"], global_code_wait)
        smsbower_code_wait = _stored_integer(values["SMSBOWER_CODE_WAIT"], global_code_wait)

        try:
            channel_priority = normalize_channel_priority(
                values["SMS_CHANNEL_PRIORITY"], allowed=self._CHANNELS
            )
        except ValueError:
            channel_priority = []
        if not channel_priority:
            # Default: Hero first (historical behavior), smsbower after it only
            # when it has been configured.
            channel_priority = ["hero"] + (["smsbower"] if smsbower_configured else [])

        hero_channel = {
            "provider": "hero",
            "countries": countries,
            "min_price": min_price,
            "max_price": max_price,
            "preferred_price": preferred_price,
            "country_prices": _country_prices_from_env(values["HERO_SMS_COUNTRY_PRICES"]),
            "acquire_priority": acquire_priority,
            "credential_configured": configured,
            "code_wait": hero_code_wait,
        }
        smsbower_channel = {
            "provider": "smsbower",
            "countries": smsbower_countries,
            "min_price": smsbower_min,
            "max_price": smsbower_max,
            "preferred_price": smsbower_preferred,
            "country_prices": _country_prices_from_env(values["SMSBOWER_COUNTRY_PRICES"]),
            "acquire_priority": smsbower_priority,
            "credential_configured": smsbower_configured,
            "code_wait": smsbower_code_wait,
        }
        return {
            "provider": "hero",
            "country": countries[0] if countries else "",
            "countries": countries,
            "service": "dr",
            "min_price": min_price,
            "max_price": max_price,
            "preferred_price": preferred_price,
            "country_prices": _country_prices_from_env(values["HERO_SMS_COUNTRY_PRICES"]),
            "acquire_priority": acquire_priority,
            "reuse_enabled": _stored_boolean(values["HERO_SMS_REUSE_ENABLED"], False),
            "max_retries": _stored_integer(values["SMS_MAX_RETRIES"], 10),
            "code_wait": hero_code_wait,
            "credential_configured": configured,
            # Kept as a one-item object for older local UI/API consumers.
            "credentials_configured": {
                "hero": configured,
                "smsbower": smsbower_configured,
            },
            # Multi-channel view. channel_priority order == selection priority.
            "channel_priority": channel_priority,
            "channels": {"hero": hero_channel, "smsbower": smsbower_channel},
        }

    def reveal_credential(self, provider: str = "hero") -> str:
        requested = _single_line(provider or "hero", field="短信平台", max_length=20).lower()
        if requested not in self._CHANNELS:
            raise ValueError("仅支持 Hero SMS 或 smsbower 渠道")
        key = "HERO_SMS_API_KEY" if requested == "hero" else "SMSBOWER_API_KEY"
        with self._lock:
            return self._values()[key].strip()

    def save(self, payload: Mapping) -> dict:
        requested_provider = _single_line(
            payload.get("provider", "hero"),
            field="短信平台",
            max_length=20,
        ).lower()
        # The upstream SMS lifecycle stays Hero-anchored (SMS_PROVIDER=hero);
        # smsbower is layered on as an additional receiving channel, so the
        # top-level provider field is still restricted to Hero.
        if requested_provider not in {"", "hero"}:
            raise ValueError("上游短信模块固定为 Hero SMS，附加渠道请通过 channel_priority / smsbower 配置")

        with self._lock:
            current = self._values()

        # Channel priority: accept the modern `channel_priority` field, and the
        # legacy `provider_order` alias. Order defines selection priority.
        priority_source = (
            payload.get("channel_priority")
            if "channel_priority" in payload
            else payload.get("provider_order")
        )
        if priority_source is not None:
            channel_priority = normalize_channel_priority(priority_source, allowed=self._CHANNELS)
        else:
            try:
                channel_priority = normalize_channel_priority(
                    current["SMS_CHANNEL_PRIORITY"], allowed=self._CHANNELS
                )
            except ValueError:
                channel_priority = []

        current_country = str(current["SMS_COUNTRY"] or "").strip()
        current_fallback = (current_country,) if current_country.isdigit() else ()
        try:
            current_countries = normalize_hero_countries(
                current["HERO_SMS_COUNTRIES"],
                fallback=current_fallback,
            )
        except ValueError:
            current_countries = list(current_fallback)

        if "countries" in payload or "hero_countries" in payload:
            countries = normalize_hero_countries(payload.get("countries", payload.get("hero_countries")))
        elif "country" in payload:
            first = _single_line(payload.get("country"), field="Hero SMS 国家 ID", max_length=12)
            countries = normalize_hero_countries([first, *current_countries[1:]])
        else:
            countries = current_countries
        if not countries:
            raise ValueError("Hero SMS 至少需要选择 1 个国家")

        service = _single_line(payload.get("service", "dr"), field="服务代码", max_length=64).lower()
        if service not in {"", "dr", "openai", "chatgpt"}:
            raise ValueError("Hero SMS 服务已固定为 OpenAI（dr）")

        min_price = normalize_price(
            payload.get("min_price", current["HERO_SMS_MIN_PRICE"]),
            field="最低购买价",
        )
        max_price = (
            normalize_price(
                payload.get(
                    "max_price",
                    current["HERO_SMS_MAX_PRICE"] or current["SMS_MAX_PRICE"],
                ),
                field="价格上限",
            )
            or "0.11"
        )
        preferred_price = normalize_price(
            payload.get("preferred_price", current["HERO_SMS_PREFERRED_PRICE"]),
            field="指定价格档位",
        )
        _validate_price_range(min_price, max_price, preferred_price)
        # Per-country prices are the authoritative pricing now. Every selected
        # country must carry a max price (fixed defaults to False).
        hero_country_prices = normalize_country_prices(
            payload.get("country_prices", current["HERO_SMS_COUNTRY_PRICES"]),
            countries,
            channel="hero",
        )
        acquire_priority = _single_line(
            payload.get("acquire_priority", current["HERO_SMS_ACQUIRE_PRIORITY"] or "country"),
            field="拿号优先级",
            max_length=20,
        ).lower()
        if acquire_priority not in {"country", "price", "price_high"}:
            raise ValueError("拿号优先级仅支持 country / price / price_high")
        reuse_enabled = _boolean(
            payload.get("reuse_enabled", _stored_boolean(current["HERO_SMS_REUSE_ENABLED"], False)),
            field="号码复用",
        )

        # ---- smsbower channel (optional, parallel to Hero) ----
        smsbower_payload = payload.get("smsbower")
        smsbower_payload = smsbower_payload if isinstance(smsbower_payload, Mapping) else {}

        def _sb_current(name: str) -> str:
            return current[name]

        if "countries" in smsbower_payload:
            smsbower_countries = normalize_hero_countries(smsbower_payload.get("countries"))
        else:
            try:
                smsbower_countries = normalize_hero_countries(current["SMSBOWER_COUNTRIES"])
            except ValueError:
                smsbower_countries = []
        smsbower_min = normalize_price(
            smsbower_payload.get("min_price", _sb_current("SMSBOWER_MIN_PRICE")),
            field="最低购买价",
        )
        smsbower_max = normalize_price(
            smsbower_payload.get("max_price", _sb_current("SMSBOWER_MAX_PRICE")),
            field="价格上限",
        )
        smsbower_preferred = normalize_price(
            smsbower_payload.get("preferred_price", _sb_current("SMSBOWER_PREFERRED_PRICE")),
            field="指定价格档位",
        )
        _validate_price_range(smsbower_min, smsbower_max, smsbower_preferred)
        # Per-country prices for smsbower (required only for its own countries).
        smsbower_country_prices = normalize_country_prices(
            smsbower_payload.get("country_prices", current["SMSBOWER_COUNTRY_PRICES"]),
            smsbower_countries,
            channel="smsbower",
        )
        smsbower_priority = _single_line(
            smsbower_payload.get(
                "acquire_priority", current["SMSBOWER_ACQUIRE_PRIORITY"] or "country"
            ),
            field="拿号优先级",
            max_length=20,
        ).lower()
        if smsbower_priority not in {"country", "price", "price_high"}:
            raise ValueError("拿号优先级仅支持 country / price / price_high")

        # Per-channel SMS-code wait. Hero keeps the legacy top-level `code_wait`
        # field (which also seeds the global SMS_CODE_WAIT fallback); smsbower
        # reads its own `code_wait` from the nested smsbower payload.
        hero_code_wait = _integer(
            payload.get(
                "code_wait",
                current["HERO_SMS_CODE_WAIT"] or current["SMS_CODE_WAIT"] or 30,
            ),
            field="短信等待秒数",
            minimum=30,
            maximum=600,
        )
        smsbower_code_wait = _integer(
            smsbower_payload.get(
                "code_wait",
                current["SMSBOWER_CODE_WAIT"] or hero_code_wait,
            ),
            field="短信等待秒数",
            minimum=30,
            maximum=600,
        )
        smsbower_credential = _single_line(
            smsbower_payload.get("credential"), field="smsbower API Key"
        )
        smsbower_key_present = (
            bool(smsbower_credential)
            or (bool(current["SMSBOWER_API_KEY"].strip()) and smsbower_payload.get("clear_credential") is not True)
        )
        if "smsbower" in channel_priority and not (smsbower_key_present and smsbower_countries):
            raise ValueError("启用 smsbower 渠道前需配置其 API Key 和至少 1 个国家")

        updates = {
            "SMS_PROVIDER": "hero",
            "SMS_COUNTRY": countries[0],
            "SMS_SERVICE": "dr",
            "SMS_MAX_PRICE": max_price,
            # No user-facing换号次数 anymore: exhaust every channel × country
            # combination once. This env key is retained only for the vendor
            # protocol-mode loop; derive it from the configured slot count with a
            # sane floor so that loop also walks all combos instead of a fixed 10.
            "SMS_MAX_RETRIES": str(
                max(
                    len(countries) + len(smsbower_countries),
                    len(countries),
                    1,
                )
            ),
            "SMS_CODE_WAIT": hero_code_wait,
            "HERO_SMS_COUNTRIES": ",".join(countries),
            "HERO_SMS_MIN_PRICE": min_price,
            "HERO_SMS_MAX_PRICE": max_price,
            "HERO_SMS_PREFERRED_PRICE": preferred_price,
            "HERO_SMS_COUNTRY_PRICES": json.dumps(hero_country_prices, ensure_ascii=False),
            "HERO_SMS_ACQUIRE_PRIORITY": acquire_priority,
            "HERO_SMS_REUSE_ENABLED": "true" if reuse_enabled else "false",
            "HERO_SMS_CODE_WAIT": hero_code_wait,
            "SMS_CHANNEL_PRIORITY": ",".join(channel_priority),
            "SMSBOWER_COUNTRIES": ",".join(smsbower_countries),
            "SMSBOWER_MIN_PRICE": smsbower_min,
            "SMSBOWER_MAX_PRICE": smsbower_max,
            "SMSBOWER_PREFERRED_PRICE": smsbower_preferred,
            "SMSBOWER_COUNTRY_PRICES": json.dumps(smsbower_country_prices, ensure_ascii=False),
            "SMSBOWER_ACQUIRE_PRIORITY": smsbower_priority,
            "SMSBOWER_CODE_WAIT": smsbower_code_wait,
        }
        credential = _single_line(payload.get("credential"), field="Hero SMS API Key")
        if payload.get("clear_credential") is True:
            updates["HERO_SMS_API_KEY"] = ""
        elif credential:
            updates["HERO_SMS_API_KEY"] = credential
        if smsbower_payload.get("clear_credential") is True:
            updates["SMSBOWER_API_KEY"] = ""
        elif smsbower_credential:
            updates["SMSBOWER_API_KEY"] = smsbower_credential

        with self._lock:
            self._write(updates)
            for key in _REMOVED_PROVIDER_KEYS:
                os.environ.pop(key, None)
            for key, value in updates.items():
                os.environ[key] = value
        return self.snapshot()

    def _write(self, updates: Mapping[str, str]) -> None:
        self.env_path.parent.mkdir(parents=True, exist_ok=True)
        original = self.env_path.read_text(encoding="utf-8") if self.env_path.is_file() else ""
        lines = original.splitlines()
        pending = dict(updates)
        update_keys = set(updates)
        written: set[str] = set()
        output: list[str] = []
        for line in lines:
            match = _ENV_LINE.match(line)
            key = match.group("key") if match else None
            if key in _REMOVED_PROVIDER_KEYS:
                continue
            if key in update_keys:
                if key in written:
                    continue
                prefix = match.group("prefix")
                output.append(f"{prefix}{key}={_env_value(updates[key])}")
                written.add(key)
                pending.pop(key, None)
            else:
                output.append(line)
        if pending:
            if output and output[-1].strip():
                output.append("")
            output.append("# ---- Hero SMS settings ----")
            output.extend(f"{key}={_env_value(value)}" for key, value in pending.items())

        temporary = self.env_path.parent / f".{self.env_path.name}.{secrets.token_hex(8)}.tmp"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write("\n".join(output).rstrip("\n") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.env_path)
            try:
                os.chmod(self.env_path, 0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = [
    "SmsConfigStore",
    "normalize_channel_priority",
    "normalize_country_prices",
    "normalize_hero_countries",
    "normalize_price",
]
