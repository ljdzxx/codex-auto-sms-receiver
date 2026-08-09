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
from urllib.parse import parse_qs, urlencode, urlsplit

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


def _split_password_totp(line: str) -> list[str] | None:
    """Split a ``密码 + TOTP 2FA`` import line into ``[email, password, secret]``.

    Both ``email|password|secret`` and ``email----password----secret`` are
    accepted, and any extra columns after the secret (备注/其他扩展字段) are
    ignored instead of failing the line.  The password itself may contain the
    separator, so candidate layouts are tried in order and the first one whose
    third column is a valid Base32 secret wins.
    """

    line = str(line or "")
    for separator in ("----", "|"):
        if separator not in line:
            continue
        columns = [column.strip() for column in line.split(separator)]
        if len(columns) < 3:
            continue
        candidates = [columns[:3]]
        if len(columns) > 3:
            # Legacy tolerance: the password may embed the separator, in which
            # case the secret is the last column (old first/last "|" behaviour).
            candidates.append(
                [columns[0], separator.join(columns[1:-1]).strip(), columns[-1]]
            )
        for candidate in candidates:
            if not all(candidate):
                continue
            try:
                normalize_totp_secret(candidate[2])
            except ValueError:
                continue
            return candidate
    return None


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
            "signup_password": str(record.get("signup_password") or ""),
            "otp_ready": otp_ready,
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "codex_status": record.get("codex_status") or "",
            "codex_message": record.get("codex_message") or "",
            "has_credential": bool(record.get("credential_path")),
            "phone_verified": bool(record.get("phone_verified")),
            "phone_number": str(record.get("phone_number") or ""),
            "phone_verified_at": record.get("phone_verified_at"),
            # gcash 提炼 outcome. The accessToken itself stays private (export
            # only), the list API just says whether one was captured.
            "gcash_status": str(record.get("gcash_status") or ""),
            "gcash_message": str(record.get("gcash_message") or ""),
            "has_gcash_token": bool(record.get("gcash_access_token")),
            "gcash_updated_at": record.get("gcash_updated_at"),
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
                columns = _split_password_totp(line)
                if columns is None:
                    invalid += 1
                    continue
                parts = columns
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
                        "import_material": line,
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
                parsed.append(
                    {"email": parts[0], "code_url": code_url, "import_material": line}
                )
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
                        "import_material": line,
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
                for key in (
                    "password",
                    "client_id",
                    "refresh_token",
                    "code_url",
                    "totp_secret",
                    "import_material",
                ):
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

    @staticmethod
    def _original_material(record: Mapping) -> str:
        """Return a re-importable line in the account's original source format."""

        preserved = str(record.get("import_material") or "").strip()
        if preserved:
            return preserved
        email = str(record.get("email") or "").strip()
        source = str(record.get("source") or "").strip().lower()
        if source == "outlook":
            return "----".join(
                (
                    email,
                    str(record.get("password") or ""),
                    str(record.get("client_id") or ""),
                    str(record.get("refresh_token") or ""),
                )
            )
        if source == "password_totp":
            return "|".join(
                (
                    email,
                    str(record.get("password") or ""),
                    str(record.get("totp_secret") or ""),
                )
            )
        if source in _URL_OTP_SOURCES:
            code_url = str(record.get("code_url") or "").strip()
            material = code_url
            if source == "generic_api":
                try:
                    parsed = urlsplit(code_url)
                    if (
                        parsed.scheme.casefold() == "https"
                        and parsed.netloc.casefold() == "icloud.xbovo.online"
                        and parsed.path == "/api/v1/code"
                    ):
                        values = parse_qs(parsed.query)
                        if values.get("key"):
                            material = values["key"][0]
                except ValueError:
                    pass
            return f"{email}----{material}"
        return email

    def export_original(self, account_ids: list[str]) -> dict[str, list[str]]:
        """Group selected account materials by import source without exposing them to list APIs."""

        normalized = [str(value or "").strip() for value in account_ids]
        if not normalized or any(not value for value in normalized):
            raise ValueError("请至少选择一个账号")
        with self._lock:
            records = self._read()
            missing = [value for value in normalized if value not in records]
            if missing:
                raise KeyError("所选账号不存在")
            grouped: dict[str, list[str]] = {}
            for account_id in normalized:
                record = records[account_id]
                source = str(record.get("source") or "unknown").strip().lower()
                grouped.setdefault(source, []).append(self._original_material(record))
            return grouped

    def delete_many(self, account_ids: list[str]) -> int:
        normalized = list(dict.fromkeys(str(value or "").strip() for value in account_ids))
        if not normalized or any(not value for value in normalized):
            raise ValueError("请至少选择一个账号")
        with self._lock:
            records = self._read()
            if any(value not in records for value in normalized):
                raise KeyError("所选账号不存在")
            for account_id in normalized:
                del records[account_id]
            self._write(records)
        return len(normalized)

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

    def update_gcash(
        self,
        email: str,
        *,
        status: str | None = None,
        access_token: str | None = None,
        link: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Record gcash 提炼 progress for one account.

        Only the fields that are passed get written, so the accessToken captured
        at the login step survives a later failure of the extraction step (the
        export needs it for both groups).
        """
        with self._lock:
            records = self._read()
            record = records.get(self._id(email))
            if record is None:
                return False
            if status is not None:
                record["gcash_status"] = str(status or "")
            if access_token is not None:
                record["gcash_access_token"] = str(access_token or "")
            if link is not None:
                record["gcash_link"] = str(link or "")
            if message is not None:
                record["gcash_message"] = str(message or "")
            record["gcash_updated_at"] = _now()
            record["updated_at"] = _now()
            self._write(records)
            return True

    def export_gcash(self, account_ids: list[str]) -> dict[str, list[str]]:
        """Group selected accounts' 提炼 results into 成功 / 失败 buckets.

        Each line is the account's original import material with the captured
        accessToken appended, separated by ``----`` — the same separator the
        import parser already understands for the leading columns.
        """
        normalized = list(dict.fromkeys(str(value or "").strip() for value in account_ids))
        if not normalized or any(not value for value in normalized):
            raise ValueError("请至少选择一个账号")
        with self._lock:
            records = self._read()
            missing = [value for value in normalized if value not in records]
            if missing:
                raise KeyError("所选账号不存在")
            grouped: dict[str, list[str]] = {"success": [], "failed": []}
            for account_id in normalized:
                record = records[account_id]
                status = str(record.get("gcash_status") or "").strip().lower()
                if status not in {"success", "failed"}:
                    continue
                token = str(record.get("gcash_access_token") or "").strip()
                material = self._original_material(record)
                grouped[status].append(f"{material}----{token}" if token else material)
            return grouped

    def update_signup_password(self, email: str, signup_password: str) -> bool:
        password = str(signup_password or "")
        if not password:
            return False
        with self._lock:
            records = self._read()
            account_id = self._id(email)
            record = records.get(account_id)
            if record is None:
                return False
            record["signup_password"] = password
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
