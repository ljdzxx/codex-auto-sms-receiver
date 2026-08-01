from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class LogRetentionPolicy:
    """Bound local raw-log growth without touching recent active work."""

    max_age_days: int = 30
    max_files: int = 1000
    max_total_bytes: int = 200 * 1024 * 1024
    protect_recent_seconds: int = 3600

    @classmethod
    def from_environment(cls) -> "LogRetentionPolicy":
        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(str(os.getenv(name, default)).strip())
            except (TypeError, ValueError):
                value = default
            return max(minimum, min(maximum, value))

        return cls(
            max_age_days=integer("LOG_RETENTION_DAYS", 30, 1, 3650),
            max_files=integer("LOG_MAX_FILES", 1000, 20, 100000),
            max_total_bytes=integer("LOG_MAX_TOTAL_MB", 200, 20, 10240) * 1024 * 1024,
            protect_recent_seconds=integer("LOG_PROTECT_RECENT_SECONDS", 3600, 60, 86400),
        )


def _inside(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def maintain_log_retention(
    log_dir: Path,
    *,
    policy: LogRetentionPolicy | None = None,
    active_paths: Iterable[Path | str] = (),
    now: float | None = None,
) -> dict[str, int]:
    """Delete only old/excess ``*.log`` files contained by ``log_dir``.

    Recent files and explicitly active worker logs are protected.  Files are
    removed oldest-first until age, count and total-size limits are all met.
    Symlinks are ignored so cleanup can never follow a link outside the log
    directory.
    """

    selected = policy or LogRetentionPolicy.from_environment()
    root = Path(log_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    current_time = float(time.time() if now is None else now)
    active: set[Path] = set()
    for value in active_paths:
        try:
            path = Path(value).resolve()
        except (OSError, RuntimeError):
            continue
        if _inside(root, path):
            active.add(path)

    rows: list[dict[str, object]] = []
    for path in root.rglob("*.log"):
        try:
            if path.is_symlink():
                continue
            resolved = path.resolve(strict=True)
            if not _inside(root, resolved):
                continue
            stat = resolved.stat()
        except (OSError, RuntimeError):
            continue
        rows.append(
            {
                "path": resolved,
                "mtime": float(stat.st_mtime),
                "size": int(stat.st_size),
                "active": resolved in active,
            }
        )

    rows.sort(key=lambda item: (float(item["mtime"]), str(item["path"])))
    total_bytes = sum(int(item["size"]) for item in rows)
    remaining = len(rows)
    cutoff = current_time - (selected.max_age_days * 86400)
    recent_cutoff = current_time - selected.protect_recent_seconds
    deleted_files = 0
    deleted_bytes = 0
    errors = 0

    for item in rows:
        over_age = float(item["mtime"]) < cutoff
        over_count = remaining > selected.max_files
        over_size = total_bytes > selected.max_total_bytes
        if not (over_age or over_count or over_size):
            continue
        if bool(item["active"]) or float(item["mtime"]) >= recent_cutoff:
            continue
        target = Path(item["path"])
        if not _inside(root, target):
            errors += 1
            continue
        try:
            target.unlink()
        except OSError:
            errors += 1
            continue
        size = int(item["size"])
        remaining -= 1
        total_bytes -= size
        deleted_files += 1
        deleted_bytes += size

    return {
        "scanned_files": len(rows),
        "remaining_files": remaining,
        "remaining_bytes": max(0, total_bytes),
        "deleted_files": deleted_files,
        "deleted_bytes": deleted_bytes,
        "errors": errors,
    }


__all__ = ["LogRetentionPolicy", "maintain_log_retention"]
