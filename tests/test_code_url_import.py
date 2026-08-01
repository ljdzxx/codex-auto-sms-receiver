from pathlib import Path

import pytest

from src.mailbox_store import MailboxStore


def test_code_url_is_a_distinct_ready_account_source(tmp_path: Path):
    store = MailboxStore(tmp_path)

    result = store.import_text(
        "code_url",
        "owner@example.com----https://mail.example.test/inbox/token",
    )

    assert result == {"parsed": 1, "inserted": 1, "updated": 0, "invalid": 0}
    public = store.list_accounts()[0]
    assert public["source"] == "code_url"
    assert public["otp_ready"] is True
    assert "code_url" not in public
    assert store.get_secret(email="owner@example.com")["code_url"] == (
        "https://mail.example.test/inbox/token"
    )


@pytest.mark.parametrize("value", ["api-key-only", "ftp://mail.example.test/code"])
def test_code_url_requires_an_http_url(tmp_path: Path, value: str):
    store = MailboxStore(tmp_path)

    with pytest.raises(ValueError, match="没有解析到"):
        store.import_text("code_url", f"owner@example.com----{value}")
