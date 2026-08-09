from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from typing import Any


class BrowserBridgeTimeout(RuntimeError):
    pass


class BrowserContextBridge:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._pending: deque[str] = deque()
        self._requests: dict[str, dict[str, Any]] = {}
        self._last_client_seen = 0.0

    def mark_client_seen(self) -> None:
        with self._changed:
            self._last_client_seen = time.time()
            self._changed.notify_all()

    def client_recently_seen(self, *, within_seconds: int = 30) -> bool:
        with self._lock:
            return (time.time() - self._last_client_seen) <= max(1, within_seconds)

    def request(self, kind: str, payload: dict[str, Any] | None = None, *, timeout: float = 120.0) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        record = {
            "id": request_id,
            "kind": str(kind or "").strip(),
            "payload": dict(payload or {}),
            "created_at": time.time(),
            "status": "pending",
            "response": None,
            "claimed": False,
        }
        deadline = time.time() + max(1.0, float(timeout))
        with self._changed:
            self._requests[request_id] = record
            self._pending.append(request_id)
            self._changed.notify_all()
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    self._requests.pop(request_id, None)
                    raise BrowserBridgeTimeout(f"浏览器桥接超时：{record['kind']}")
                current = self._requests.get(request_id)
                if not current:
                    raise BrowserBridgeTimeout(f"浏览器桥接请求丢失：{record['kind']}")
                if current.get("status") == "done":
                    response = current.get("response")
                    self._requests.pop(request_id, None)
                    return response if isinstance(response, dict) else {}
                self._changed.wait(timeout=min(remaining, 1.0))

    def poll_next(self, *, wait_timeout: float = 25.0) -> dict[str, Any] | None:
        deadline = time.time() + max(0.0, float(wait_timeout))
        with self._changed:
            self._last_client_seen = time.time()
            while True:
                while self._pending:
                    request_id = self._pending[0]
                    current = self._requests.get(request_id)
                    if not current:
                        self._pending.popleft()
                        continue
                    if current.get("status") != "pending":
                        self._pending.popleft()
                        continue
                    if current.get("claimed"):
                        break
                    current["claimed"] = True
                    return {
                        "id": current["id"],
                        "kind": current["kind"],
                        "payload": current["payload"],
                    }
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._changed.wait(timeout=min(remaining, 1.0))

    def resolve(self, request_id: str, response: dict[str, Any] | None = None) -> bool:
        with self._changed:
            current = self._requests.get(str(request_id or ""))
            if current is None:
                return False
            current["status"] = "done"
            current["response"] = dict(response or {})
            if self._pending and self._pending[0] == current["id"]:
                self._pending.popleft()
            self._last_client_seen = time.time()
            self._changed.notify_all()
            return True


browser_bridge = BrowserContextBridge()


__all__ = ["BrowserBridgeTimeout", "BrowserContextBridge", "browser_bridge"]
