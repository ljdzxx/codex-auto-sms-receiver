from __future__ import annotations

from src.hero_pricing import (
    HERO_SMS_API_BASE,
    HeroPricingClient,
    extract_price_tiers,
    filter_price_tiers,
)


class FakeResponse:
    def __init__(self, payload, *, text="", status_code=200):
        self._payload = payload
        self.text = text
        self.status_code = status_code

    def json(self):
        return self._payload


def test_extracts_stocked_price_tiers_and_filters_range():
    payload = {
        "33": {
            "dr": {
                "0.0400": {"count": 0},
                "0.075": {"count": 4},
                "0.1200": {"count": 2},
            }
        }
    }

    tiers = extract_price_tiers(payload)
    assert tiers == [
        {"price": "0.04", "stock": 0, "available": False},
        {"price": "0.075", "stock": 4, "available": True},
        {"price": "0.12", "stock": 2, "available": True},
    ]
    assert filter_price_tiers(tiers, min_price="0.05", max_price="0.1") == [
        {"price": "0.075", "stock": 4, "available": True}
    ]


def test_client_queries_both_price_catalogs_for_openai():
    calls = []

    def fake_get(url, *, params, headers, timeout):
        calls.append((url, dict(params), dict(headers), timeout))
        return FakeResponse({"33": {"dr": {"cost": 0.08, "count": 3}}})

    rows = HeroPricingClient("saved-key", http_get=fake_get).prices(["33"])

    assert rows[0]["country"] == "33"
    assert rows[0]["tiers"] == [
        {"price": "0.08", "stock": 3, "available": True}
    ]
    assert [item[1]["action"] for item in calls] == ["getPricesExtended", "getPrices"]
    assert all(item[0] == HERO_SMS_API_BASE for item in calls)
    assert all(item[1]["service"] == "dr" for item in calls)
    assert all(item[1]["api_key"] == "saved-key" for item in calls)


def test_zero_balance_is_a_valid_balance():
    def fake_get(url, *, params, headers, timeout):
        return FakeResponse("ACCESS_BALANCE:0", text="ACCESS_BALANCE:0")

    assert HeroPricingClient("saved-key", http_get=fake_get).balance() == {"amount": "0"}
