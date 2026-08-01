import os
from pathlib import Path

from src.log_retention import LogRetentionPolicy, maintain_log_retention


def _log(path: Path, *, size: int, mtime: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    os.utime(path, (mtime, mtime))
    return path


def test_retention_removes_old_files_but_protects_recent_and_active(tmp_path: Path):
    now = 2_000_000_000.0
    root = tmp_path / "logs"
    old = _log(root / "old.log", size=10, mtime=now - 40 * 86400)
    active = _log(root / "active.log", size=10, mtime=now - 40 * 86400)
    recent = _log(root / "recent.log", size=10, mtime=now - 30)

    result = maintain_log_retention(
        root,
        policy=LogRetentionPolicy(
            max_age_days=30,
            max_files=100,
            max_total_bytes=1000,
            protect_recent_seconds=3600,
        ),
        active_paths=[active],
        now=now,
    )

    assert old.exists() is False
    assert active.exists() is True
    assert recent.exists() is True
    assert result["deleted_files"] == 1
    assert result["remaining_files"] == 2


def test_retention_enforces_count_and_size_oldest_first(tmp_path: Path):
    now = 2_000_000_000.0
    root = tmp_path / "logs"
    files = [
        _log(root / f"item-{index}.log", size=40, mtime=now - 7200 + index)
        for index in range(5)
    ]

    result = maintain_log_retention(
        root,
        policy=LogRetentionPolicy(
            max_age_days=365,
            max_files=3,
            max_total_bytes=100,
            protect_recent_seconds=60,
        ),
        now=now,
    )

    assert [path.exists() for path in files] == [False, False, False, True, True]
    assert result["remaining_files"] == 2
    assert result["remaining_bytes"] == 80


def test_environment_policy_is_bounded(monkeypatch):
    monkeypatch.setenv("LOG_RETENTION_DAYS", "0")
    monkeypatch.setenv("LOG_MAX_FILES", "999999")
    monkeypatch.setenv("LOG_MAX_TOTAL_MB", "bad")

    policy = LogRetentionPolicy.from_environment()

    assert policy.max_age_days == 1
    assert policy.max_files == 100000
    assert policy.max_total_bytes == 200 * 1024 * 1024
