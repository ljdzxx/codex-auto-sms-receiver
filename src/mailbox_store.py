from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import urlencode, urlsplit

from .totp_auth import normalize_totp_secret


_ICLOUD_CODE_API_BASE = "https://icloud.xbovo.online/api/v1/code"
_URL_OTP_SOURCES = {"generic_api", "code_url"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_code_url(value: str) -> str:
    """Validate a user-supplied HTTP(S) mailbox/OTP page URL."""

    value = str(value or "").strip()
    lower = value.casefold()
    if lower.startswith(("http://", "https://")):
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("取码地址包含无效字符")
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("取码地址格式无效") from exc
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("取码地址必须是有效的 HTTP(S) URL")
        return value
    raise ValueError("取码地址必须是 HTTP(S) URL")


def _generic_code_url(email: str, credential: str) -> str:
    """Accept a full endpoint URL or expand an iCloud mailbox API key."""

    value = str(credential or "").strip()
    lower = value.casefold()
    if lower.startswith(("http://", "https://")) or "://" in value:
        return _validate_code_url(value)
    if not value or len(value) > 2048 or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("API Key 格式无效")
    return f"{_ICLOUD_CODE_API_BASE}?{urlencode({'email': email, 'key': value})}"


class MailboxStore:
    """Private local store for already-registered account mailbox access."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "mailboxes.json"
        self._lock = threading.RLock()

    def _read(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"无法读取邮箱素材: {exc}") from exc
        return value if isinstance(value, dict) else {}

    def _write(self, records: Mapping[str, Mapping]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.data_dir / f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(records, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    @staticmethod
    def _id(email: str) -> str:
        return hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _public(record: Mapping) -> dict:
        source = str(record.get("source") or "")
        if source in _URL_OTP_SOURCES:
            otp_ready = bool(record.get("code_url"))
        elif source == "password_totp":
            otp_ready = bool(record.get("password") and record.get("totp_secret"))
        else:
            otp_ready = bool(record.get("client_id") and record.get("refresh_token"))
        return {
            "id": record.get("id"),
            "email": record.get("email"),
            "source": record.get("source"),
            "otp_ready": otp_ready,
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "codex_status": record.get("codex_status") or "",
            "codex_message": record.get("codex_message") or "",
            "has_credential": bool(record.get("credential_path")),
            "phone_verified": bool(record.get("phone_verified")),
            "phone_number": str(record.get("phone_number") or ""),
            "phone_verified_at": record.get("phone_verified_at"),
        }

    def list_accounts(self) -> list[dict]:
        with self._lock:
            records = self._read()
            rows = [self._public(record) for record in records.values()]
        rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
        return rows

    def get_secret(self, *, account_id: str | None = None, email: str | None = None) -> dict | None:
        with self._lock:
            records = self._read()
            if account_id:
                record = records.get(str(account_id))
            else:
                target = str(email or "").strip().casefold()
                record = next(
                    (item for item in records.values() if str(item.get("email") or "").casefold() == target),
                    None,
                )
            return deepcopy(record) if record else None

    def import_text(self, source: str, text: str) -> dict:
        source = str(source or "").strip().lower()
        if source not in {"outlook", "generic_api", "code_url", "password_totp"}:
            raise ValueError("source 仅支持 outlook / generic_api / code_url / password_totp")
        parsed: list[dict] = []
        invalid = 0
        for raw in str(text or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if source == "password_totp":
                first_separator = line.find("|")
                last_separator = line.rfind("|")
                if first_separator <= 0 or last_separator <= first_separator:
                    invalid += 1
                    continue
                parts = [
                    line[:first_separator],
                    line[first_separator + 1:last_separator],
                    line[last_separator + 1:],
                ]
            elif source in _URL_OTP_SOURCES:
                parts = line.split("----", 1) if "----" in line else line.split("====", 1)
            else:
                parts = line.split("----") if "----" in line else line.split("====")
            parts = [part.strip() for part in parts]
            if source == "outlook":
                if len(parts) < 4 or not parts[0] or not parts[2] or not parts[3]:
                    invalid += 1
                    continue
                parsed.append(
                    {
                        "email": parts[0],
                        "password": parts[1],
                        "client_id": parts[2],
                        "refresh_token": parts[3],
                    }
                )
            elif source in _URL_OTP_SOURCES:
                if len(parts) < 2 or not parts[0] or not parts[1]:
                    invalid += 1
                    continue
                try:
                    code_url = (
                        _validate_code_url(parts[1])
                        if source == "code_url"
                        else _generic_code_url(parts[0], parts[1])
                    )
                except ValueError:
                    invalid += 1
                    continue
                parsed.append({"email": parts[0], "code_url": code_url})
            else:
                if len(parts) != 3 or not all(parts):
                    invalid += 1
                    continue
                try:
                    totp_secret = normalize_totp_secret(parts[2])
                except ValueError:
                    invalid += 1
                    continue
                parsed.append(
                    {
                        "email": parts[0],
                        "password": parts[1],
                        "totp_secret": totp_secret,
                    }
                )
        if not parsed:
            raise ValueError("没有解析到有效邮箱素材")

        inserted = updated = 0
        with self._lock:
            records = self._read()
            for item in parsed:
                email = item["email"].strip()
                account_id = self._id(email)
                now = _now()
                existing = records.get(account_id)
                record = existing or {
                    "id": account_id,
                    "email": email,
                    "created_at": now,
                    "codex_status": "",
                    "codex_message": "",
                    "credential_path": None,
                }
                for key in ("password", "client_id", "refresh_token", "code_url", "totp_secret"):
                    record.pop(key, None)
                record.update(item)
                record["source"] = source
                record["updated_at"] = now
                records[account_id] = record
                if existing:
                    updated += 1
                else:
                    inserted += 1
            self._write(records)
        return {"parsed": len(parsed), "inserted": inserted, "updated": updated, "invalid": invalid}

    def update_codex(
        self,
        email: str,
        *,
        status: str,
        message: str = "",
        credential_path: str | None = None,
        phone_verified: bool | None = None,
        phone_number: str | None = None,
    ) -> bool:
        with self._lock:
            records = self._read()
            account_id = self._id(email)
            record = records.get(account_id)
            if record is None:
                return False
            record["codex_status"] = status
            record["codex_message"] = message
            if credential_path is not None:
                record["credential_path"] = credential_path
            if phone_verified is not None:
                record["phone_verified"] = bool(phone_verified)
                if phone_verified:
                    record["phone_verified_at"] = _now()
            if phone_number is not None:
                record["phone_number"] = str(phone_number or "")
            record["updated_at"] = _now()
            self._write(records)
            return True

    def delete(self, account_id: str) -> bool:
        with self._lock:
            records = self._read()
            if str(account_id) not in records:
                return False
            del records[str(account_id)]
            self._write(records)
            return True
