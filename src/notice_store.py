from __future__ import annotations

import threading
from typing import Any


# 进程内的一次性提示队列：worker 线程写、侧边栏轮询读。
# 只服务于"让用户看见程序正在做什么"，所以既不落盘也不保证送达——
# 侧边栏没开的时候这些提示本来就没有意义。
_MAX_NOTICES = 200


class NoticeStore:
    """Transient, in-process notices for the side panel to toast.

    The pipeline worker runs as a thread in this same process, so a plain
    in-memory ring buffer is enough — no file, no IPC. Each notice gets a
    monotonically increasing sequence number and the panel asks for everything
    newer than the last one it showed, which makes the transport idempotent
    (a dropped poll just means the panel catches up on the next one).
    """

    def __init__(self, limit: int = _MAX_NOTICES):
        self._lock = threading.Lock()
        self._items: list[dict[str, Any]] = []
        self._seq = 0
        self._limit = max(1, int(limit))

    def push(self, message: str, *, level: str = "info", scope: str = "") -> int:
        text = str(message or "").strip()
        if not text:
            return self._seq
        with self._lock:
            self._seq += 1
            self._items.append(
                {
                    "seq": self._seq,
                    "message": text[:300],
                    "level": str(level or "info"),
                    "scope": str(scope or ""),
                }
            )
            if len(self._items) > self._limit:
                del self._items[: len(self._items) - self._limit]
            return self._seq

    def since(self, after: int) -> dict[str, Any]:
        """Notices newer than ``after``. ``after<0`` means "just tell me where we are"."""

        with self._lock:
            if after < 0:
                # First poll: don't replay history as a burst of toasts.
                return {"seq": self._seq, "notices": []}
            items = [item for item in self._items if item["seq"] > after]
            return {"seq": self._seq, "notices": items}


# 单例：worker 线程和 Flask 视图都用这一个。
notices = NoticeStore()


__all__ = ["NoticeStore", "notices"]
