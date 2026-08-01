from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"


def _find_browser_executable() -> Path | None:
    configured = os.getenv("BROWSER_EXECUTABLE", "").strip()
    candidates = [
        Path(configured) if configured else None,
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ]
    return next((item for item in candidates if item is not None and item.is_file()), None)


@dataclass(frozen=True)
class Settings:
    project_root: Path
    data_dir: Path
    log_dir: Path
    browser_executable: Path | None
    browser_timeout_seconds: int
    host: str
    port: int


def load_settings(*, host: str | None = None, port: int | None = None) -> Settings:
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return Settings(
        project_root=PROJECT_ROOT,
        data_dir=DATA_DIR,
        log_dir=LOG_DIR,
        browser_executable=_find_browser_executable(),
        browser_timeout_seconds=max(60, int(os.getenv("LOGIN_TIMEOUT_SECONDS", "600"))),
        host=(host or os.getenv("WEBUI_HOST", "127.0.0.1")).strip() or "127.0.0.1",
        port=int(port or os.getenv("WEBUI_PORT", "5015")),
    )
