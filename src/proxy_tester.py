from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ip-api.com is keyless and returns Chinese place names directly; ipinfo is the
# HTTPS fallback for networks that block the plain-HTTP endpoint. Both are only
# reached *through* the proxy under test, so the answer is that proxy's exit IP.
_GEO_ENDPOINTS = (
    (
        "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,query&lang=zh-CN",
        "ip-api",
    ),
    ("https://ipinfo.io/json", "ipinfo"),
)
_TEST_TIMEOUT = 12.0
_MAX_PARALLEL_TESTS = 6


def _location_from_ip_api(payload: dict[str, Any]) -> tuple[str, str, str]:
    if str(payload.get("status") or "").lower() != "success":
        return "", "", str(payload.get("message") or "取地理位置失败")
    parts = [payload.get("country"), payload.get("regionName"), payload.get("city")]
    seen: list[str] = []
    for part in parts:
        text = str(part or "").strip()
        if text and text not in seen:
            seen.append(text)
    return str(payload.get("query") or ""), " · ".join(seen), ""

def _location_from_ipinfo(payload: dict[str, Any]) -> tuple[str, str, str]:
    parts = [payload.get("country"), payload.get("region"), payload.get("city")]
    seen: list[str] = []
    for part in parts:
        text = str(part or "").strip()
        if text and text not in seen:
            seen.append(text)
    return str(payload.get("ip") or ""), " · ".join(seen), ""


def _readable_error(exc: requests.RequestException) -> str:
    """Turn a requests exception into a short Chinese reason for the table.

    The raw text is a multi-line urllib3 blob (pool, retries, nested cause) that
    tells an operator nothing useful about *their* proxy, so classify the common
    cases and keep only a short tail for anything unexpected.
    """
    if isinstance(exc, requests.exceptions.ProxyError):
        return "无法连接到代理（地址/端口错误，或代理已下线）"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "连接代理超时"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "代理响应超时"
    if isinstance(exc, requests.exceptions.SSLError):
        return "代理 TLS 握手失败"
    if isinstance(exc, requests.exceptions.ConnectionError):
        text = str(exc)
        if "SOCKS" in text or "socks" in text:
            return "SOCKS 代理连接失败（地址/端口错误，或需要认证）"
        return "连接失败（代理不可达或被拒绝）"
    if isinstance(exc, requests.exceptions.InvalidURL):
        return "代理地址格式无效"
    return f"{type(exc).__name__}: {str(exc)[:90]}"


def test_proxy_url(url: str, *, timeout: float = _TEST_TIMEOUT) -> dict[str, Any]:
    """Probe one proxy: reachable? exit IP? where? how slow?

    Latency is the wall time of the whole geo request through the proxy, which
    is what matters operationally (a proxy that resolves fast but tunnels slowly
    is still a slow proxy).
    """
    proxies = {"http": url, "https": url}
    last_error = ""
    for endpoint, kind in _GEO_ENDPOINTS:
        started = time.perf_counter()
        try:
            response = requests.get(
                endpoint,
                proxies=proxies,
                timeout=timeout,
                headers={"User-Agent": "codex-auto-sms-receiver/proxy-check"},
            )
        except requests.RequestException as exc:
            last_error = _readable_error(exc)
            continue
        latency_ms = int((time.perf_counter() - started) * 1000)
        if response.status_code != 200:
            last_error = f"HTTP {response.status_code}"
            continue
        try:
            payload = response.json()
        except ValueError:
            last_error = "响应不是 JSON"
            continue
        if not isinstance(payload, dict):
            last_error = "响应格式无法识别"
            continue
        ip, location, failure = (
            _location_from_ip_api(payload) if kind == "ip-api" else _location_from_ipinfo(payload)
        )
        if failure:
            last_error = failure
            continue
        if not ip:
            last_error = "未取到出口 IP"
            continue
        return {
            "ok": True,
            "ip": ip,
            "location": location,
            # Country + timezone let the browser stop contradicting its own exit
            # IP (a Chinese locale/timezone on a US datacenter address is one of
            # the loudest "this is a proxy" signals there is).
            "country_code": str(payload.get("countryCode") or payload.get("country") or "")[:2].upper(),
            "timezone": str(payload.get("timezone") or ""),
            "latency_ms": latency_ms,
            "message": "",
        }
    return {
        "ok": False,
        "ip": "",
        "location": "",
        "country_code": "",
        "timezone": "",
        "latency_ms": None,
        "message": last_error or "代理不可用",
    }


def test_proxies(records: list[dict[str, Any]], *, timeout: float = _TEST_TIMEOUT) -> list[dict[str, Any]]:
    """Test several proxies concurrently, preserving input order."""
    if not records:
        return []

    def run(record: dict[str, Any]) -> dict[str, Any]:
        result = test_proxy_url(str(record.get("url") or ""), timeout=timeout)
        result["id"] = str(record.get("id") or "")
        return result

    workers = max(1, min(_MAX_PARALLEL_TESTS, len(records)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="proxy-test") as pool:
        return list(pool.map(run, records))


__all__ = ["test_proxies", "test_proxy_url"]
