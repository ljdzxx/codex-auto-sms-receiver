from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable, Mapping

import requests


HERO_SMS_API_BASE = "https://hero-sms.com/stubs/handler_api.php"
HERO_SMS_SERVICE_CODE = "dr"
_PRICE_PATTERN = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d{1,4})?$")
_ERROR_CODES = {
    "BAD_ACTION",
    "BAD_KEY",
    "BAD_SERVICE",
    "BAD_STATUS",
    "INVALID_KEY",
    "NO_ACTIVATION",
    "NO_BALANCE",
    "NO_NUMBERS",
    "NOT_ENOUGH_BALANCE",
    "SERVICE_UNAVAILABLE_REGION",
    "WRONG_KEY",
    "WRONG_MAX_PRICE",
}
_STOCK_KEYS = (
    "physicalCount",
    "physical_count",
    "count",
    "stock",
    "available",
    "quantity",
    "qty",
    "left",
    "free",
)


class HeroPricingError(RuntimeError):
    """A deliberately redacted Hero API error safe for the WebUI."""


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    text = str(value).strip().replace(",", ".")
    if text.startswith("$"):
        text = text[1:].strip()
    if not _PRICE_PATTERN.fullmatch(text):
        return None
    try:
        parsed = Decimal(text)
    except InvalidOperation:
        return None
    if not parsed.is_finite() or parsed <= 0:
        return None
    return parsed


def decimal_text(value: Any) -> str | None:
    parsed = value if isinstance(value, Decimal) else _decimal(value)
    if parsed is None or not parsed.is_finite() or parsed <= 0:
        return None
    return format(parsed.quantize(Decimal("0.0001")).normalize(), "f")


def _stock(mapping: Mapping[str, Any]) -> tuple[bool, int | None]:
    found = False
    values: list[int] = []
    for key in _STOCK_KEYS:
        if key not in mapping:
            continue
        found = True
        value = mapping.get(key)
        if isinstance(value, bool):
            values.append(1 if value else 0)
            continue
        try:
            values.append(max(0, int(float(str(value).strip()))))
        except (TypeError, ValueError):
            continue
    if not found:
        return False, None
    return True, max(values) if values else 0


def extract_price_tiers(payload: Any) -> list[dict[str, Any]]:
    """Extract price/stock tiers from the known SMS-Activate response shapes."""

    found: dict[Decimal, int | None] = {}

    def add(price_value: Any, stock_value: int | None) -> None:
        price = _decimal(price_value)
        if price is None:
            return
        previous = found.get(price)
        if previous is None:
            # Keep an explicit stock count when one is available; otherwise the
            # tier remains usable with an unknown count.
            found[price] = stock_value
        elif stock_value is not None:
            found[price] = max(previous, stock_value)

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, list):
            for item in node:
                visit(item, depth + 1)
            return
        if not isinstance(node, Mapping):
            return

        direct_price = node.get("cost", node.get("price", node.get("rate")))
        has_stock, stock_count = _stock(node)
        if direct_price is not None:
            add(direct_price, stock_count if has_stock else None)

        for raw_key, value in node.items():
            key = str(raw_key).strip()
            keyed_price = _decimal(key)
            if keyed_price is not None and isinstance(value, Mapping):
                keyed_has_stock, keyed_stock = _stock(value)
                # Requiring a stock field avoids misreading country/service IDs
                # as price keys in nested directory responses.
                if keyed_has_stock:
                    add(keyed_price, keyed_stock)
            elif keyed_price is not None and "." in key:
                try:
                    add(keyed_price, max(0, int(float(str(value).strip()))))
                except (TypeError, ValueError):
                    pass
            visit(value, depth + 1)

    visit(payload)
    rows = []
    for price in sorted(found):
        stock_count = found[price]
        rows.append(
            {
                "price": decimal_text(price),
                "stock": stock_count,
                "available": stock_count is None or stock_count > 0,
            }
        )
    return rows


def merge_price_tiers(payloads: Iterable[Any]) -> list[dict[str, Any]]:
    merged: dict[Decimal, int | None] = {}
    for payload in payloads:
        for row in extract_price_tiers(payload):
            price = _decimal(row.get("price"))
            if price is None:
                continue
            stock = row.get("stock")
            previous = merged.get(price)
            if previous is None:
                merged[price] = stock if isinstance(stock, int) else None
            elif isinstance(stock, int):
                merged[price] = max(previous, stock)
    return [
        {
            "price": decimal_text(price),
            "stock": merged[price],
            "available": merged[price] is None or merged[price] > 0,
        }
        for price in sorted(merged)
    ]


def filter_price_tiers(
    tiers: Iterable[Mapping[str, Any]],
    *,
    min_price: Any = None,
    max_price: Any = None,
) -> list[dict[str, Any]]:
    minimum = _decimal(min_price)
    maximum = _decimal(max_price)
    rows: list[dict[str, Any]] = []
    for item in tiers:
        price = _decimal(item.get("price"))
        if price is None:
            continue
        if minimum is not None and price < minimum:
            continue
        if maximum is not None and price > maximum:
            continue
        rows.append(dict(item))
    return rows


def _payload_text(response: Any) -> tuple[Any, str]:
    raw_text = str(getattr(response, "text", "") or "").strip()
    try:
        return response.json(), raw_text
    except Exception:
        pass
    if raw_text and raw_text[:1] in {'"', "{", "["}:
        try:
            return json.loads(raw_text), raw_text
        except (TypeError, ValueError):
            pass
    return raw_text, raw_text


def _error_code(payload: Any, raw_text: str = "") -> str:
    if isinstance(payload, Mapping):
        candidate = str(
            payload.get("title")
            or payload.get("error")
            or payload.get("errorCode")
            or payload.get("error_code")
            or ""
        ).strip().upper()
        if candidate:
            return re.sub(r"[^A-Z0-9_-]", "_", candidate)[:80]
    text = str(payload if isinstance(payload, str) else raw_text or "").strip().upper()
    if text in _ERROR_CODES:
        return text
    if text.startswith("WRONG_MAX_PRICE"):
        return "WRONG_MAX_PRICE"
    return ""


class HeroPricingClient:
    """Backend-only Hero balance and OpenAI price/stock client."""

    def __init__(
        self,
        api_key: str,
        *,
        http_get: Callable[..., Any] | None = None,
        timeout_seconds: int = 20,
    ) -> None:
        self._api_key = str(api_key or "").strip()
        self._http_get = http_get or requests.get
        self._timeout_seconds = max(3, min(60, int(timeout_seconds)))

    def _request(self, action: str, **params: Any) -> Any:
        if not self._api_key:
            raise HeroPricingError("Hero SMS API Key 尚未配置")
        query = {"api_key": self._api_key, "action": action, **params}
        try:
            response = self._http_get(
                HERO_SMS_API_BASE,
                params=query,
                headers={"User-Agent": "codex-auto-sms-receiver/1.0", "Accept": "application/json,text/plain"},
                timeout=self._timeout_seconds,
            )
        except Exception as exc:
            # Never echo an HTTP exception: clients commonly include the full
            # URL, which would expose api_key.
            raise HeroPricingError(f"Hero SMS 网络请求失败（{type(exc).__name__}）") from exc

        status_code = int(getattr(response, "status_code", 0) or 0)
        payload, raw_text = _payload_text(response)
        code = _error_code(payload, raw_text)
        if code:
            raise HeroPricingError(f"Hero SMS {code}")
        if status_code != 200:
            raise HeroPricingError(f"Hero SMS HTTP {status_code or 'unknown'}")
        return payload

    def balance(self) -> dict[str, Any]:
        payload = self._request("getBalance")
        value: Any = None
        if isinstance(payload, str):
            value = re.sub(r"^ACCESS_BALANCE:", "", payload.strip(), flags=re.IGNORECASE)
        elif isinstance(payload, Mapping):
            data = payload.get("data")
            source = data if isinstance(data, Mapping) else payload
            value = source.get("balance", source.get("amount"))
        try:
            amount = Decimal(str(value).strip().replace(",", "."))
        except (InvalidOperation, ValueError):
            amount = Decimal("-1")
        if not amount.is_finite() or amount < 0:
            raise HeroPricingError("Hero SMS 余额响应格式不正确")
        amount_text = format(amount.quantize(Decimal("0.0001")).normalize(), "f")
        return {"amount": amount_text}

    def prices(self, country_ids: Iterable[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for raw_country_id in country_ids:
            country_id = str(raw_country_id or "").strip()
            payloads: list[Any] = []
            failures: list[HeroPricingError] = []
            for action, extra in (
                ("getPricesExtended", {"freePrice": "true"}),
                ("getPrices", {}),
            ):
                try:
                    payloads.append(
                        self._request(
                            action,
                            service=HERO_SMS_SERVICE_CODE,
                            country=country_id,
                            **extra,
                        )
                    )
                except HeroPricingError as exc:
                    failures.append(exc)
            if not payloads:
                raise failures[-1] if failures else HeroPricingError("Hero SMS 价格查询失败")
            tiers = merge_price_tiers(payloads)
            known_stocks = [row["stock"] for row in tiers if isinstance(row.get("stock"), int)]
            results.append(
                {
                    "country": country_id,
                    "tiers": tiers,
                    "available": any(bool(row.get("available")) for row in tiers),
                    "total_stock": sum(known_stocks) if known_stocks else None,
                }
            )
        return results


__all__ = [
    "HERO_SMS_API_BASE",
    "HERO_SMS_SERVICE_CODE",
    "HeroPricingClient",
    "HeroPricingError",
    "decimal_text",
    "extract_price_tiers",
    "filter_price_tiers",
    "merge_price_tiers",
]
