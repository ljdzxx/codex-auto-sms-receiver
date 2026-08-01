from __future__ import annotations

from src.hero_catalog import HeroCatalog, _normalize_countries


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_country_directory_exposes_names_and_sorts_popular_first():
    rows = _normalize_countries(
        {
            "999": {"id": 999, "chn": "测试国", "eng": "Testland", "visible": 1},
            "52": {"id": 52, "chn": "泰国", "eng": "Thailand", "visible": 1},
            "16": {"id": 16, "chn": "英格兰", "eng": "United Kingdom", "visible": 1},
            "0": {"id": 0, "chn": "隐藏", "eng": "Hidden", "visible": 0},
        }
    )

    assert [row["id"] for row in rows] == ["16", "52", "999"]
    assert rows[0]["name"] == "英国"
    assert rows[1]["name"] == "泰国"
    assert rows[1]["flag"] == "🇹🇭"
    assert rows[2]["name_en"] == "Testland"


def test_catalog_fetches_without_api_key_and_uses_cache():
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"52": {"id": 52, "chn": "泰国", "eng": "Thailand"}})

    catalog = HeroCatalog(http_get=fake_get, clock=lambda: 100.0)
    first = catalog.catalog()
    second = catalog.catalog()

    assert first["source"] == "live"
    assert first["service"] == {"code": "dr", "name": "OpenAI"}
    assert first["countries"][0]["name"] == "泰国"
    assert second == first
    assert len(calls) == 1
    assert calls[0][1]["params"] == {"action": "getCountries", "lang": "cn"}
    assert "api_key" not in calls[0][1]["params"]


def test_catalog_falls_back_to_named_popular_countries():
    def failing_get(*args, **kwargs):
        raise TimeoutError("offline")

    result = HeroCatalog(http_get=failing_get).catalog()

    assert result["source"] == "fallback"
    assert len(result["countries"]) >= 15
    assert any(row["name"] == "泰国" and row["id"] == "52" for row in result["countries"])
