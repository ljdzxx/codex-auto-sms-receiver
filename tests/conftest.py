import os

import pytest


@pytest.fixture(autouse=True)
def _restore_os_environ():
    """Guarantee os.environ isolation across tests.

    SmsConfigStore.save() writes settings straight into os.environ. pytest's
    monkeypatch.delenv on an already-absent key records nothing to undo, so those
    direct writes would otherwise leak into later test modules (e.g. a saved
    HERO_SMS_PREFERRED_PRICE bleeding into hero_sms strategy tests). Snapshotting
    and restoring the whole environment makes every test start from a clean slate
    regardless of how a store mutates the process environment.
    """

    saved = dict(os.environ)
    # settings.py calls load_dotenv() at import, so the developer's local .env
    # (channel priority, per-provider prices/keys) can bleed into os.environ and
    # steer tests that only clear a subset of keys. Strip the SMS-related keys so
    # every test starts from a provider-neutral baseline regardless of .env.
    for key in list(os.environ):
        if key.startswith(("SMS_", "HERO_SMS_", "SMSBOWER_")):
            os.environ.pop(key, None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)
