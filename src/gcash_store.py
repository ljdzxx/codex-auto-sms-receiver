from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class GcashTabStore:
    """Persist which browser tabs gcash 提炼 drives.

    The binding is picked by the operator in the extension's 调试 page and has to
    reach the worker process, which never talks to the extension UI directly —
    hence a small JSON file next to the other local state. Tab ids are only
    meaningful for the current browser run, so a stale file simply fails the
    next run with "标签页已不存在" instead of silently driving a wrong tab.
    """

    FILENAME = "gcash-tabs.json"

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / self.FILENAME
        self._lock = threading.RLock()

    def _read(self) -> dict:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _tab_id(value: object) -> int | None:
        try:
            number = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        return number if number >= 0 else None

    def get(self) -> dict:
        with self._lock:
            payload = self._read()
        return {
            "login_tab_id": self._tab_id(payload.get("login_tab_id")),
            "extract_tab_id": self._tab_id(payload.get("extract_tab_id")),
            "login_tab_label": str(payload.get("login_tab_label") or ""),
            "extract_tab_label": str(payload.get("extract_tab_label") or ""),
            "updated_at": payload.get("updated_at"),
        }

    def save(
        self,
        *,
        login_tab_id: object,
        extract_tab_id: object,
        login_tab_label: str = "",
        extract_tab_label: str = "",
    ) -> dict:
        login = self._tab_id(login_tab_id)
        extract = self._tab_id(extract_tab_id)
        if login is None or extract is None:
            raise ValueError("请为「ChatGPT登录」和「153提炼」各选择一个标签页")
        if login == extract:
            raise ValueError("两个标签页不能是同一个")
        record = {
            "login_tab_id": login,
            "extract_tab_id": extract,
            "login_tab_label": str(login_tab_label or "")[:300],
            "extract_tab_label": str(extract_tab_label or "")[:300],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            temporary = self.data_dir / f".{self.FILENAME}.tmp"
            temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(self.path)
        return self.get()
