"""
Test manual register_status editing via the account editor.
"""

import json
import tempfile
from pathlib import Path

import pytest

from src.mailbox_store import MailboxStore


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield MailboxStore(data_dir=Path(tmpdir))


def test_register_status_can_be_manually_edited(store):
    """
    用户可以在账号编辑器里手动修改 register_status（pending/registered/success/failed）。
    """
    # 导入一个 smsbower_gmail 账号，初始状态 pending
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    accounts = store.list_accounts()
    assert len(accounts) == 1
    account = accounts[0]
    assert account["register_status"] == "pending"

    # 手动改成 failed
    updated = store.update_manual_credentials(
        account["id"],
        register_status="failed",
    )
    assert updated["register_status"] == "failed"

    # 再改成 registered
    updated = store.update_manual_credentials(
        account["id"],
        register_status="registered",
    )
    assert updated["register_status"] == "registered"

    # 改成 success
    updated = store.update_manual_credentials(
        account["id"],
        register_status="success",
    )
    assert updated["register_status"] == "success"

    # 改回 pending
    updated = store.update_manual_credentials(
        account["id"],
        register_status="pending",
    )
    assert updated["register_status"] == "pending"


def test_empty_register_status_keeps_original_value(store):
    """
    传空字符串或不传 register_status = 保持原值。
    """
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    account = store.list_accounts()[0]
    assert account["register_status"] == "pending"

    # 空字符串 = 保持原值
    updated = store.update_manual_credentials(
        account["id"],
        register_status="",
    )
    assert updated["register_status"] == "pending"

    # 不传 = 保持原值
    updated = store.update_manual_credentials(
        account["id"],
        plus_trial=True,  # 只改别的字段
    )
    assert updated["register_status"] == "pending"
    assert updated["plus_trial"] is True


def test_manual_codex_status_matches_the_status_shown_in_account_list(store):
    """编辑器修改的是清单“最近任务”实际展示的 codex_status。"""
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    account = store.list_accounts()[0]
    store.update_codex("test@example.com", status="failed", message="注册流程失败")

    before = store.list_accounts()[0]
    assert before["codex_status"] == "failed"
    assert before["register_status"] == "pending"

    updated = store.update_manual_credentials(account["id"], codex_status="success")
    assert updated["codex_status"] == "success"
    assert updated["codex_message"] == "已手动标记为成功"
    assert updated["register_status"] == "pending"

    persisted = store.list_accounts()[0]
    assert persisted["codex_status"] == "success"
    assert persisted["codex_message"] == "已手动标记为成功"


def test_password_and_secret_together_override_manual_register_status(store):
    """
    密码 + 2FA 密钥齐了，会自动改写成 success，即使用户手动指定了别的状态。
    这是注册成功的标准路径，优先级高于手动编辑。
    """
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    account = store.list_accounts()[0]

    # 同时提供密码、密钥、和 register_status=failed
    updated = store.update_manual_credentials(
        account["id"],
        password="Test1234!@#$",
        totp_secret="JBSWY3DPEHPK3PXP",  # 合法的 Base32
        register_status="failed",  # 这个会被自动改写覆盖
    )

    # 自动改写逻辑优先：密码 + 密钥齐了 → 改成 password_totp + success
    assert updated["source"] == "password_totp"
    assert updated["register_status"] == "success"
    assert updated["register_message"] == "已手动补全密码和 2FA 密钥"
    assert updated["otp_ready"] is True


def test_manual_register_status_without_credentials_takes_effect(store):
    """
    如果只改 register_status、不补密码/密钥，则手动指定的状态生效。
    """
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    account = store.list_accounts()[0]

    # 只改状态，不补凭证
    updated = store.update_manual_credentials(
        account["id"],
        register_status="failed",
    )

    # 手动状态生效
    assert updated["register_status"] == "failed"
    assert updated["source"] == "smsbower_gmail"  # 类型没变
    assert updated["otp_ready"] is False  # 素材仍未就绪


def test_partial_credentials_do_not_trigger_auto_rewrite(store):
    """
    只有密码或只有密钥时，不会触发自动改写，手动 register_status 生效。
    """
    store.import_activations([{
        "email": "test@example.com",
        "mail_id": "12345",
    }])
    account = store.list_accounts()[0]

    # 只提供密码，手动状态 = registered
    updated = store.update_manual_credentials(
        account["id"],
        password="Test1234!@#$",
        register_status="registered",
    )
    assert updated["register_status"] == "registered"
    assert updated["source"] == "smsbower_gmail"  # 没有改写

    # 再补密钥，不指定状态
    updated = store.update_manual_credentials(
        account["id"],
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    # 现在密码 + 密钥齐了，自动改写成 success
    assert updated["register_status"] == "success"
    assert updated["source"] == "password_totp"
