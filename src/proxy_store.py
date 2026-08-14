from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

_SUPPORTED_SCHEMES = ("http", "https", "socks5")
_MAX_PROXIES = 500


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask_secret(value: str) -> str:
    return "***" if value else ""


def _mask_host(host: str) -> str:
    """Keep a proxy row recognisable without printing the full endpoint."""
    text = str(host or "")
    if not text:
        return ""
    parts = text.split(".")
    if len(parts) >= 2 and not text.replace(".", "").isdigit():
        head = parts[0]
        visible = head[:3] if len(head) > 3 else head
        return ".".join([f"{visible}***", *parts[1:]])
    if len(text) <= 4:
        return text
    return f"{text[:3]}***{text[-2:]}"


class ProxyParseError(ValueError):
    """A proxy line the user typed cannot be understood."""


def parse_proxy_url(value: str) -> dict[str, Any]:
    """Normalize one user-typed proxy line into structured parts.

    Accepted spellings, with the scheme optional (defaults to ``http``):
    ``host:port`` and ``user:pass@host:port``. Supported schemes are ``http``,
    ``https`` and ``socks5``. Raises :class:`ProxyParseError` with a Chinese
    message for invalid input.
    """

    raw = str(value or "").strip()
    if not raw:
        raise ProxyParseError("代理地址为空")
    if len(raw) > 512:
        raise ProxyParseError("代理地址过长")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ProxyParseError("代理地址包含空白或控制字符")

    scheme = "http"
    rest = raw
    if "://" in raw:
        scheme_part, rest = raw.split("://", 1)
        scheme = scheme_part.strip().lower()
        if scheme not in _SUPPORTED_SCHEMES:
            raise ProxyParseError(f"不支持的代理协议：{scheme_part}")
    if not rest:
        raise ProxyParseError("代理地址缺少主机和端口")

    username = ""
    password = ""
    if "@" in rest:
        # Credentials may legitimately contain '@'; the host part never does.
        credential_part, host_part = rest.rsplit("@", 1)
        if ":" in credential_part:
            username, password = credential_part.split(":", 1)
        else:
            username = credential_part
        username = unquote(username)
        password = unquote(password)
    else:
        host_part = rest

    host_part = host_part.strip().rstrip("/")
    if host_part.count(":") != 1:
        raise ProxyParseError("代理地址必须是 host:port 形式")
    host, port_text = host_part.split(":", 1)
    host = host.strip()
    if not host:
        raise ProxyParseError("代理地址缺少主机")
    try:
        port = int(port_text)
    except (TypeError, ValueError):
        raise ProxyParseError(f"代理端口无效：{port_text}") from None
    if not 1 <= port <= 65535:
        raise ProxyParseError(f"代理端口超出范围：{port}")

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


def build_proxy_url(parts: dict[str, Any]) -> str:
    scheme = str(parts.get("scheme") or "http")
    host = str(parts.get("host") or "")
    port = int(parts.get("port") or 0)
    username = str(parts.get("username") or "")
    password = str(parts.get("password") or "")
    credential = ""
    if username:
        credential = quote(username, safe="")
        if password:
            credential += ":" + quote(password, safe="")
        credential += "@"
    return f"{scheme}://{credential}{host}:{port}"


def masked_proxy_url(parts: dict[str, Any]) -> str:
    scheme = str(parts.get("scheme") or "http")
    host = _mask_host(str(parts.get("host") or ""))
    port = parts.get("port")
    username = str(parts.get("username") or "")
    password = str(parts.get("password") or "")
    credential = ""
    if username:
        credential = _mask_secret(username)
        if password:
            credential += ":" + _mask_secret(password)
        credential += "@"
    return f"{scheme}://{credential}{host}:{port}"


def proxy_id(parts: dict[str, Any]) -> str:
    """Stable id from the endpoint, so re-adding the same proxy updates it."""
    key = f"{parts.get('scheme')}://{parts.get('username')}@{parts.get('host')}:{parts.get('port')}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


class ProxyStore:
    """Local proxy pool for the browser-driven pipeline.

    Only the extension can actually route browser traffic, so this store keeps
    the pool plus a round-robin cursor and hands each account the next proxy at
    dispatch time (mirroring how gcash tab bindings reach the worker). Nothing
    here talks to the network; testing lives in :mod:`proxy_tester`.
    """

    FILENAME = "proxies.json"

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / self.FILENAME
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- storage
    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"enabled": False, "cursor": 0, "proxies": []}
        if not isinstance(payload, dict):
            return {"enabled": False, "cursor": 0, "proxies": []}
        proxies = payload.get("proxies")
        return {
            "enabled": bool(payload.get("enabled")),
            "cursor": int(payload.get("cursor") or 0),
            "proxies": [item for item in proxies if isinstance(item, dict)] if isinstance(proxies, list) else [],
        }

    def _write(self, state: dict[str, Any]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.data_dir / f".{self.FILENAME}.tmp"
        temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    # ------------------------------------------------------------------ views
    @staticmethod
    def _public(record: dict[str, Any]) -> dict[str, Any]:
        """Row shape the extension renders. The raw URL never leaves the store."""
        return {
            "id": str(record.get("id") or ""),
            "url_masked": str(record.get("url_masked") or ""),
            "scheme": str(record.get("scheme") or "http"),
            "label": str(record.get("label") or ""),
            "enabled": bool(record.get("enabled")),
            "has_auth": bool(record.get("username")),
            "status": str(record.get("status") or "untested"),
            "ip": str(record.get("ip") or ""),
            "location": str(record.get("location") or ""),
            "latency_ms": record.get("latency_ms"),
            "message": str(record.get("message") or ""),
            "tested_at": record.get("tested_at"),
            "created_at": record.get("created_at"),
        }

    def state(self) -> dict[str, Any]:
        with self._lock:
            state = self._read()
        rows = [self._public(item) for item in state["proxies"]]
        return {
            "enabled": state["enabled"],
            "proxies": rows,
            "summary": {
                "total": len(rows),
                "active": sum(1 for row in rows if row["enabled"]),
                "untested": sum(1 for row in rows if row["status"] == "untested"),
                "failed": sum(1 for row in rows if row["status"] == "failed"),
            },
        }

    def get_raw(self, proxy_id_value: str) -> dict[str, Any] | None:
        """Full record including credentials — for testing and for the browser."""
        target = str(proxy_id_value or "").strip()
        with self._lock:
            for item in self._read()["proxies"]:
                if str(item.get("id") or "") == target:
                    return dict(item)
        return None

    # ----------------------------------------------------------------- writes
    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        with self._lock:
            state = self._read()
            state["enabled"] = bool(enabled)
            self._write(state)
        return self.state()

    def add_many(self, text: str, label: str = "") -> dict[str, Any]:
        lines = [line.strip() for line in str(text or "").splitlines()]
        lines = [line for line in lines if line and not line.startswith("#")]
        if not lines:
            raise ProxyParseError("请至少填写一行代理地址")
        inserted = 0
        updated = 0
        invalid: list[str] = []
        with self._lock:
            state = self._read()
            existing = {str(item.get("id") or ""): item for item in state["proxies"]}
            for line in lines:
                try:
                    parts = parse_proxy_url(line)
                except ProxyParseError as exc:
                    invalid.append(f"{line} —— {exc}")
                    continue
                identifier = proxy_id(parts)
                record = existing.get(identifier)
                if record is None:
                    if len(state["proxies"]) >= _MAX_PROXIES:
                        raise ProxyParseError(f"代理池最多保存 {_MAX_PROXIES} 条")
                    record = {
                        "id": identifier,
                        "enabled": True,
                        "status": "untested",
                        "ip": "",
                        "location": "",
                        "latency_ms": None,
                        "message": "",
                        "tested_at": None,
                        "created_at": _now(),
                    }
                    state["proxies"].append(record)
                    existing[identifier] = record
                    inserted += 1
                else:
                    updated += 1
                record.update(
                    scheme=parts["scheme"],
                    host=parts["host"],
                    port=parts["port"],
                    username=parts["username"],
                    password=parts["password"],
                    url=build_proxy_url(parts),
                    url_masked=masked_proxy_url(parts),
                )
                if label:
                    record["label"] = str(label)[:60]
                record.setdefault("label", "")
            self._write(state)
        result = self.state()
        result.update(inserted=inserted, updated=updated, invalid=invalid)
        return result

    def set_proxy_enabled(self, proxy_id_value: str, enabled: bool) -> dict[str, Any]:
        target = str(proxy_id_value or "").strip()
        with self._lock:
            state = self._read()
            for item in state["proxies"]:
                if str(item.get("id") or "") == target:
                    item["enabled"] = bool(enabled)
                    break
            else:
                raise KeyError("代理不存在")
            self._write(state)
        return self.state()

    def delete(self, proxy_id_value: str) -> dict[str, Any]:
        target = str(proxy_id_value or "").strip()
        with self._lock:
            state = self._read()
            remaining = [item for item in state["proxies"] if str(item.get("id") or "") != target]
            if len(remaining) == len(state["proxies"]):
                raise KeyError("代理不存在")
            state["proxies"] = remaining
            self._write(state)
        return self.state()

    def record_test(
        self,
        proxy_id_value: str,
        *,
        ok: bool,
        ip: str = "",
        location: str = "",
        latency_ms: int | None = None,
        message: str = "",
        country_code: str = "",
        timezone: str = "",
    ) -> dict[str, Any] | None:
        target = str(proxy_id_value or "").strip()
        with self._lock:
            state = self._read()
            for item in state["proxies"]:
                if str(item.get("id") or "") == target:
                    item.update(
                        status="ok" if ok else "failed",
                        ip=str(ip or ""),
                        location=str(location or ""),
                        latency_ms=int(latency_ms) if isinstance(latency_ms, int) else None,
                        message=str(message or "")[:300],
                        tested_at=_now(),
                    )
                    # Keep the last known geo when a later test fails: it is still
                    # the right locale/timezone for this endpoint.
                    if country_code:
                        item["country_code"] = str(country_code)[:2].upper()
                    if timezone:
                        item["timezone"] = str(timezone)[:64]
                    self._write(state)
                    return self._public(item)
        return None

    # ------------------------------------------------------------ round-robin
    def next_for_account(self) -> dict[str, Any] | None:
        """Take the next enabled proxy and advance the persisted cursor.

        Returns ``None`` when the pool is off or empty, which means "let the
        browser use the direct connection". The cursor survives restarts so a
        second batch continues where the previous one stopped instead of always
        hammering the first proxy.
        """
        with self._lock:
            state = self._read()
            if not state["enabled"]:
                return None
            usable = [item for item in state["proxies"] if item.get("enabled")]
            if not usable:
                return None
            index = int(state.get("cursor") or 0) % len(usable)
            chosen = usable[index]
            state["cursor"] = (index + 1) % len(usable)
            self._write(state)
            return dict(chosen)

    @staticmethod
    def browser_config(record: dict[str, Any] | None) -> dict[str, Any] | None:
        """Shape a record for ``chrome.proxy`` (fixed_servers + auth + geo).

        ``country_code`` / ``timezone`` come from the last successful test and let
        the browser stop contradicting its own exit IP: a zh-CN locale and an
        Asia/Shanghai clock on a US datacenter address is one of the loudest
        "this session is proxied" signals a site can read.
        """
        if not record:
            return None
        # http / https / socks5 are exactly the fixed_servers scheme names, and
        # the value was validated on the way in, so no translation is needed.
        scheme = str(record.get("scheme") or "http")
        return {
            "id": str(record.get("id") or ""),
            "scheme": scheme,
            "host": str(record.get("host") or ""),
            "port": int(record.get("port") or 0),
            "username": str(record.get("username") or ""),
            "password": str(record.get("password") or ""),
            "label": str(record.get("url_masked") or ""),
            "country_code": str(record.get("country_code") or ""),
            "timezone": str(record.get("timezone") or ""),
        }


__all__ = [
    "ProxyParseError",
    "ProxyStore",
    "build_proxy_url",
    "masked_proxy_url",
    "parse_proxy_url",
    "proxy_id",
]
