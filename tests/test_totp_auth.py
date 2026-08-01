import pytest

from src.totp_auth import current_totp, normalize_totp_secret


def test_normalize_totp_secret_accepts_common_spacing_and_case():
    assert normalize_totp_secret("jbsw y3dp-ehpk3pxp") == "JBSWY3DPEHPK3PXP"


def test_current_totp_matches_rfc_6238_sha1_vector_truncated_to_six_digits():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert current_totp(secret, now=59) == "287082"


@pytest.mark.parametrize("value", ["", "not-base32", "JBSWY3DP"])
def test_invalid_totp_secret_is_rejected(value):
    with pytest.raises(ValueError, match="2FA 密钥"):
        normalize_totp_secret(value)
