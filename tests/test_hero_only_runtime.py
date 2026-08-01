from pathlib import Path
from types import SimpleNamespace

from src.codex_service import CodexJobManager
from src.mailbox_store import MailboxStore
from src import upstream_bridge


def test_runtime_environment_forces_hero_and_removes_provider_order(monkeypatch, tmp_path: Path):
    (tmp_path / ".env").write_text(
        "SMS_PROVIDER=unsupported\n"
        "SMS_PROVIDER_ORDER=hero,unsupported\n"
        "SMS_SERVICE=other\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SMS_PROVIDER", "unsupported")
    monkeypatch.setenv("SMS_PROVIDER_ORDER", "hero,unsupported")
    monkeypatch.setenv("SMS_SERVICE", "other")
    monkeypatch.setenv("CODEX_OAUTH_DRIVER", "roxy")

    upstream_bridge._load_runtime_environment(SimpleNamespace(project_root=tmp_path))

    import os

    assert os.environ["SMS_PROVIDER"] == "hero"
    assert os.environ["SMS_SERVICE"] == "dr"
    assert os.environ["CODEX_OAUTH_DRIVER"] == "protocol"
    assert "SMS_PROVIDER_ORDER" not in os.environ


def test_protocol_availability_requires_hero_key_and_country(monkeypatch, tmp_path: Path):
    project_root = Path(__file__).resolve().parents[1]
    settings = SimpleNamespace(project_root=project_root)
    manager = CodexJobManager(settings, MailboxStore(tmp_path / "data"))
    monkeypatch.setenv("CODEX_OAUTH_DRIVER", "protocol")
    monkeypatch.setenv("CODEX_AUTH_URL_SOURCE", "local")
    monkeypatch.delenv("HERO_SMS_API_KEY", raising=False)
    monkeypatch.delenv("HERO_SMS_COUNTRIES", raising=False)

    missing_key = manager.availability()
    assert missing_key["available"] is False
    assert "HERO_SMS_API_KEY" in missing_key["reason"]

    monkeypatch.setenv("HERO_SMS_API_KEY", "configured")
    missing_country = manager.availability()
    assert missing_country["available"] is False
    assert "至少需要选择 1 个国家" in missing_country["reason"]

    monkeypatch.setenv("HERO_SMS_COUNTRIES", "33,187")
    available = manager.availability()
    assert available == {"available": True, "reason": ""}
    assert manager.runtime_config()["sms_provider"] == "hero"
    assert "sms_provider_order" not in manager.runtime_config()


def test_non_protocol_driver_is_rejected(monkeypatch, tmp_path: Path):
    project_root = Path(__file__).resolve().parents[1]
    manager = CodexJobManager(
        SimpleNamespace(project_root=project_root),
        MailboxStore(tmp_path / "data"),
    )
    monkeypatch.setenv("CODEX_OAUTH_DRIVER", "roxy")

    result = manager.availability()

    assert result["available"] is False
    assert "仅支持 CODEX_OAUTH_DRIVER=protocol" in result["reason"]


def test_public_job_metadata_does_not_expose_local_paths(tmp_path: Path):
    project_root = Path(__file__).resolve().parents[1]
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "codex.log"
    log_path.write_text("safe log", encoding="utf-8")
    manager = CodexJobManager(
        SimpleNamespace(
            project_root=project_root,
            data_dir=tmp_path / "data",
            log_dir=log_dir,
        ),
        MailboxStore(tmp_path / "data"),
    )
    public = manager._public_job(
        {
            "id": "job-1",
            "status": "running",
            "log_path": str(log_path),
            "credential_path": r"F:\\private\\credential.json",
        }
    )
    assert "log_path" not in public
    assert "credential_path" not in public
    assert public["has_log"] is True
    assert public["has_credential"] is True
