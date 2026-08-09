import os
from pathlib import Path

import pytest
from dotenv import dotenv_values

from src.sms_config import SmsConfigStore


SMS_ENV_KEYS = (
    "SMS_PROVIDER",
    "SMS_PROVIDER_ORDER",
    "SMS_API_KEY",
    "SMS_COUNTRY",
    "SMS_SERVICE",
    "SMS_MAX_PRICE",
    "SMS_MAX_RETRIES",
    "SMS_CODE_WAIT",
    "HERO_SMS_API_KEY",
    "HERO_SMS_COUNTRIES",
    "HERO_SMS_MIN_PRICE",
    "HERO_SMS_MAX_PRICE",
    "HERO_SMS_PREFERRED_PRICE",
    "HERO_SMS_COUNTRY_PRICES",
    "HERO_SMS_ACQUIRE_PRIORITY",
    "HERO_SMS_REUSE_ENABLED",
    "HERO_SMS_CODE_WAIT",
    "SMS_CHANNEL_PRIORITY",
    "SMSBOWER_API_KEY",
    "SMSBOWER_COUNTRIES",
    "SMSBOWER_MIN_PRICE",
    "SMSBOWER_MAX_PRICE",
    "SMSBOWER_PREFERRED_PRICE",
    "SMSBOWER_COUNTRY_PRICES",
    "SMSBOWER_ACQUIRE_PRIORITY",
    "SMSBOWER_CODE_WAIT",
    "L_API_BASE",
    "L_ADMIN_AUTH_CODE",
    "L_PHONE_PREFIX",
    "H_API_BASE",
    "H_ADMIN_AUTH_CODE",
    "H_PHONE_PREFIX",
    "H_PHONE_ACQUIRE_MODE",
)


@pytest.fixture(autouse=True)
def clean_sms_environment(monkeypatch):
    # SmsConfigStore.save() writes directly to os.environ. monkeypatch.delenv on
    # an already-absent key records nothing to undo, so those direct writes would
    # otherwise leak into later test modules. Snapshot and fully restore instead.
    saved = {key: os.environ.get(key) for key in SMS_ENV_KEYS}
    for key in SMS_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _payload(**overrides):
    value = {
        "provider": "hero",
        "countries": ["33"],
        "service": "dr",
        "min_price": "",
        "max_price": "",
        "preferred_price": "",
        # Per-country prices are now required for every selected country.
        "country_prices": {"33": {"max": "0.11", "fixed": False}},
        "acquire_priority": "country",
        "max_retries": 8,
        "code_wait": 150,
        "credential": "hero-secret",
        "clear_credential": False,
    }
    value.update(overrides)
    return value


def test_save_is_atomic_masks_secret_and_forces_hero(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("WEBUI_PORT=5015\n# keep me\nSMS_PROVIDER=grizzly\n", encoding="utf-8")
    store = SmsConfigStore(env_path)

    snapshot = store.save(_payload())

    values = dotenv_values(env_path)
    assert values["WEBUI_PORT"] == "5015"
    assert values["SMS_PROVIDER"] == "hero"
    assert values["SMS_SERVICE"] == "dr"
    assert values["HERO_SMS_API_KEY"] == "hero-secret"
    assert snapshot["provider"] == "hero"
    assert snapshot["credential_configured"] is True
    assert snapshot["credentials_configured"] == {"hero": True, "smsbower": False}
    assert "hero-secret" not in repr(snapshot)
    assert list(tmp_path.glob(".*.tmp")) == []


def test_operator_defaults_are_applied_to_empty_hero_settings(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")

    initial = store.snapshot()
    saved = store.save(_payload(max_price="", code_wait=30))

    assert initial["max_price"] == "0.11"
    assert initial["code_wait"] == 30
    assert saved["max_price"] == "0.11"
    assert saved["code_wait"] == 30
    values = dotenv_values(tmp_path / ".env")
    assert values["HERO_SMS_MAX_PRICE"] == "0.11"
    # max_retries is no longer user-set: it is derived from the channel×country
    # slot count (1 Hero country here) so the loop exhausts every combination.
    assert values["SMS_MAX_RETRIES"] == "1"
    assert values["SMS_CODE_WAIT"] == "30"


def test_duplicate_keys_are_deduplicated_and_legacy_provider_keys_removed(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "SMS_PROVIDER=grizzly\nSMS_PROVIDER=h\n"
        "SMS_PROVIDER_ORDER=hero,grizzly,l\n"
        "SMS_API_KEY=old\nL_ADMIN_AUTH_CODE=old\nH_ADMIN_AUTH_CODE=old\n",
        encoding="utf-8",
    )
    SmsConfigStore(env_path).save(_payload(credential="new-secret"))

    text = env_path.read_text(encoding="utf-8")
    keys = {line.split("=", 1)[0] for line in text.splitlines() if "=" in line}
    assert text.count("SMS_PROVIDER=") == 1
    assert "SMS_PROVIDER_ORDER" not in keys
    assert "SMS_API_KEY" not in keys
    assert "L_ADMIN_AUTH_CODE" not in keys
    assert "H_ADMIN_AUTH_CODE" not in keys
    assert dotenv_values(env_path)["HERO_SMS_API_KEY"] == "new-secret"


def test_blank_credential_preserves_existing_and_clear_is_explicit(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    store.save(_payload(credential="first-secret"))
    store.save(_payload(credential=""))
    assert os.environ["HERO_SMS_API_KEY"] == "first-secret"

    snapshot = store.save(_payload(credential="ignored", clear_credential=True))
    assert os.environ["HERO_SMS_API_KEY"] == ""
    assert snapshot["credential_configured"] is False


def test_saved_hero_credential_can_be_revealed_explicitly(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    store.save(_payload(credential="visible-on-demand"))
    assert store.reveal_credential() == "visible-on-demand"
    assert store.reveal_credential("hero") == "visible-on-demand"
    with pytest.raises(ValueError, match="仅支持 Hero SMS"):
        store.reveal_credential("grizzly")


def test_openai_service_alias_is_normalized_to_dr(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    snapshot = store.save(_payload(service="openai"))
    assert snapshot["service"] == "dr"
    assert dotenv_values(tmp_path / ".env")["SMS_SERVICE"] == "dr"


def test_hero_saves_country_and_price_strategy(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    snapshot = store.save(
        _payload(
            countries=["33", "187", "52", "33"],
            country_prices={
                "33": {"max": "0.12", "fixed": True},
                "187": {"max": "0.12", "fixed": False},
                "52": {"max": "0.10", "fixed": False},
            },
            service="openai",
            min_price="0.0500",
            max_price="0.12",
            preferred_price="0.075",
            acquire_priority="price",
            credential="hero-key",
        )
    )

    values = dotenv_values(tmp_path / ".env")
    assert "provider_order" not in snapshot
    assert snapshot["countries"] == ["33", "187", "52"]
    assert snapshot["min_price"] == "0.05"
    assert snapshot["max_price"] == "0.12"
    assert snapshot["preferred_price"] == "0.075"
    assert snapshot["acquire_priority"] == "price"
    assert values["HERO_SMS_COUNTRIES"] == "33,187,52"
    assert values["HERO_SMS_MAX_PRICE"] == "0.12"
    assert values["SMS_MAX_PRICE"] == "0.12"


@pytest.mark.parametrize(
    "overrides",
    [
        {"countries": [str(item) for item in range(11)]},
        {"min_price": "0.2", "max_price": "0.1"},
        {"min_price": "0.05", "max_price": "0.1", "preferred_price": "0.2"},
        {"acquire_priority": "random"},
    ],
)
def test_invalid_hero_strategy_is_rejected(tmp_path: Path, overrides: dict):
    with pytest.raises(ValueError):
        SmsConfigStore(tmp_path / ".env").save(_payload(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"provider": "grizzly"},
        {"provider_order": ["hero", "l"]},
        {"countries": ["us"]},
        {"service": "telegram"},
        {"countries": ["33", "187"], "country_prices": {"33": {"max": "0.11"}}},
        {"credential": "secret\nINJECTED=yes"},
    ],
)
def test_non_hero_or_invalid_values_are_rejected(tmp_path: Path, overrides: dict):
    with pytest.raises(ValueError):
        SmsConfigStore(tmp_path / ".env").save(_payload(**overrides))


def test_smsbower_channel_is_saved_with_priority(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    snapshot = store.save(
        _payload(
            channel_priority=["smsbower", "hero"],
            smsbower={
                "credential": "smsbower-secret",
                "countries": ["7", "187"],
                "country_prices": {"7": {"max": "0.2"}, "187": {"min": "0.05", "max": "0.2"}},
                "max_price": "0.2",
                "acquire_priority": "price",
            },
        )
    )

    values = dotenv_values(tmp_path / ".env")
    assert snapshot["channel_priority"] == ["smsbower", "hero"]
    assert snapshot["channels"]["smsbower"]["countries"] == ["7", "187"]
    assert snapshot["channels"]["smsbower"]["credential_configured"] is True
    assert snapshot["credentials_configured"] == {"hero": True, "smsbower": True}
    assert values["SMS_CHANNEL_PRIORITY"] == "smsbower,hero"
    assert values["SMSBOWER_API_KEY"] == "smsbower-secret"
    assert values["SMSBOWER_COUNTRIES"] == "7,187"
    # The upstream module stays Hero-anchored regardless of channel priority.
    assert values["SMS_PROVIDER"] == "hero"
    assert "smsbower-secret" not in repr(snapshot)


def test_smsbower_credential_reveal_is_explicit(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    store.save(
        _payload(
            channel_priority=["hero", "smsbower"],
            smsbower={"credential": "sb-key", "countries": ["7"], "country_prices": {"7": {"max": "0.2"}}},
        )
    )
    assert store.reveal_credential("smsbower") == "sb-key"
    assert store.reveal_credential("hero") == "hero-secret"
    with pytest.raises(ValueError):
        store.reveal_credential("grizzly")


def test_enabling_smsbower_without_key_or_country_is_rejected(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    with pytest.raises(ValueError, match="smsbower"):
        store.save(_payload(channel_priority=["hero", "smsbower"]))
    with pytest.raises(ValueError, match="smsbower"):
        store.save(
            _payload(
                channel_priority=["hero", "smsbower"],
                smsbower={"credential": "sb-key"},
            )
        )


def test_unknown_channel_priority_is_rejected(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    with pytest.raises(ValueError):
        store.save(_payload(channel_priority=["hero", "telegram"]))


def test_per_channel_code_wait_is_saved_independently(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    snapshot = store.save(
        _payload(
            code_wait=45,
            channel_priority=["smsbower", "hero"],
            smsbower={
                "credential": "sb-key",
                "countries": ["7"],
                "country_prices": {"7": {"max": "0.2"}},
                "code_wait": 200,
            },
        )
    )

    values = dotenv_values(tmp_path / ".env")
    assert values["HERO_SMS_CODE_WAIT"] == "45"
    assert values["SMSBOWER_CODE_WAIT"] == "200"
    # Global SMS_CODE_WAIT tracks the Hero value for upstream default fallback.
    assert values["SMS_CODE_WAIT"] == "45"
    assert snapshot["code_wait"] == 45
    assert snapshot["channels"]["hero"]["code_wait"] == 45
    assert snapshot["channels"]["smsbower"]["code_wait"] == 200


def test_smsbower_code_wait_falls_back_to_global_when_unset(tmp_path: Path):
    store = SmsConfigStore(tmp_path / ".env")
    snapshot = store.save(
        _payload(
            code_wait=90,
            channel_priority=["hero", "smsbower"],
            smsbower={"credential": "sb-key", "countries": ["7"], "country_prices": {"7": {"max": "0.2"}}},
        )
    )

    # No smsbower.code_wait supplied -> falls back to the global (Hero) wait.
    assert snapshot["channels"]["smsbower"]["code_wait"] == 90
    assert dotenv_values(tmp_path / ".env")["SMSBOWER_CODE_WAIT"] == "90"


def test_save_clears_stale_provider_environment(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SMS_PROVIDER_ORDER", "hero,grizzly,l,h")
    monkeypatch.setenv("SMS_API_KEY", "old-key")
    monkeypatch.setenv("L_ADMIN_AUTH_CODE", "old-l")
    monkeypatch.setenv("H_ADMIN_AUTH_CODE", "old-h")

    SmsConfigStore(tmp_path / ".env").save(_payload())

    assert "SMS_PROVIDER_ORDER" not in os.environ
    assert "SMS_API_KEY" not in os.environ
    assert "L_ADMIN_AUTH_CODE" not in os.environ
    assert "H_ADMIN_AUTH_CODE" not in os.environ
