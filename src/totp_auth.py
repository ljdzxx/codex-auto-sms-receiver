from __future__ import annotations

import base64
import binascii
import re
import time

import pyotp


_BASE32_SECRET = re.compile(r"^[A-Z2-7]+=*$")


def normalize_totp_secret(value: str) -> str:
    """Validate and normalize an RFC 6238 Base32 secret without exposing it."""

    secret = re.sub(r"[\s-]+", "", str(value or "")).upper()
    if not secret or not _BASE32_SECRET.fullmatch(secret):
        raise ValueError("2FA 密钥不是有效的 Base32 TOTP 密钥")
    try:
        padding = "=" * (-len(secret) % 8)
        decoded = base64.b32decode(secret.rstrip("=") + padding, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("2FA 密钥不是有效的 Base32 TOTP 密钥") from exc
    if len(decoded) < 10:
        raise ValueError("2FA 密钥长度不足")
    return secret.rstrip("=")


def current_totp(
    secret: str,
    *,
    now: float | None = None,
    min_valid_seconds: float = 4.0,
) -> str:
    """Return a fresh six-digit TOTP, avoiding the end of a 30-second window."""

    normalized = normalize_totp_secret(secret)
    timestamp = time.time() if now is None else float(now)
    remaining = 30.0 - (timestamp % 30.0)
    if now is None and remaining < max(0.0, float(min_valid_seconds)):
        time.sleep(remaining + 0.25)
        timestamp = time.time()
    return pyotp.TOTP(normalized, digits=6, interval=30).at(int(timestamp))


__all__ = ["current_totp", "normalize_totp_secret"]
