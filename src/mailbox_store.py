from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, urlencode, urlsplit

from .totp_auth import normalize_totp_secret


_ICLOUD_CODE_API_BASE = "https://icloud.xbovo.online/api/v1/code"
_URL_OTP_SOURCES = {"generic_api", "code_url"}
# 登录素材类型 whose accounts are rented from smsbower instead of pasted in. They
# start out with nothing but an address and an activation id; the注册 pipeline
# fills in the password + TOTP secret later.
_SMSBOWER_GMAIL = "smsbower_gmail"
_TEXT_IMPORT_SOURCES = {"outlook", "generic_api", "code_url", "password_totp"}
# 支持人工编辑（补密码 / 2FA 密钥）的两类账号：注册出来的，以及本来就是密码+2FA 的。
# 其它类型的素材是整行粘贴进来的，改一半反而容易改坏，走重新导入更清楚。
_EDITABLE_SOURCES = {_SMSBOWER_GMAIL, "password_totp"}



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
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(records, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            # Windows: os.replace raises PermissionError while any other handle
            # (antivirus scan, sync client, backup) still has the target open —
            # and this file is fully rewritten on every status change, so the
            # collision window is real. Retry briefly.
            #
            # 和 codex_service._persist_locked 的区别：那边失败可以吞（内存状态才是
            # 权威），**这里绝对不行**——账号密码和 2FA 密钥就存在这个文件里，静默
            # 丢一次写入等于废掉一个账号。重试完还不行就照实抛，让调用方失败。
            for attempt in range(6):
                try:
                    os.replace(temporary, self.path)
                    return
                except PermissionError:
                    if attempt == 5:
                        raise
                    time.sleep(0.15 * (attempt + 1))
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _id(email: str) -> str:
        return hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _public(record: Mapping) -> dict:
        source = str(record.get("source") or "")
        if source in _URL_OTP_SOURCES:
            otp_ready = bool(record.get("code_url"))
        elif source in {"password_totp", _SMSBOWER_GMAIL}:
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
            # smsbower 租用邮箱：注册进度和活动 id。id 不是凭证，露出来方便和
            # smsbower 后台对账；密码 / 2FA 密钥仍然只走导出。
            "register_status": str(record.get("register_status") or ""),
            "register_message": str(record.get("register_message") or ""),
            "mail_id": record.get("mail_id"),
            # 人工编辑用：密钥本身**绝不出口**（只走导出），这里只说"有没有"，
            # 编辑框留空即保持原值。editable 决定清单里显不显示「编辑」按钮。
            "has_totp_secret": bool(record.get("totp_secret")),
            "origin_source": str(record.get("origin_source") or ""),
            "editable": not _EDITABLE_SOURCES.isdisjoint(
                {source, str(record.get("origin_source") or "").strip().lower()}
            ),
            # 1 个月 Plus 免费资格（None = 还没探测过）。导出时是末列 ----0/1。
            "plus_trial": record.get("plus_trial"),
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
        if source not in _TEXT_IMPORT_SOURCES:
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

    def import_activations(self, activations: list[Mapping]) -> dict:
        """Insert mailboxes rented from smsbower (no pasted material at all).

        Every entry needs an ``email`` plus the ``mail_id`` smsbower hands back,
        because the activation has to be cancelled (status=2) or closed
        (status=3) later — losing the id means the rental keeps costing money.
        An address that was already rented before simply takes the new id, and
        the id it replaces is reported back in ``superseded`` so the caller can
        hand that rental in rather than pay for an id nobody can reach.
        """

        parsed: list[dict] = []
        for item in activations:
            email = str((item or {}).get("email") or "").strip()
            try:
                mail_id = int(str((item or {}).get("mail_id") or "").strip())
            except (TypeError, ValueError):
                mail_id = 0
            if not email or mail_id <= 0:
                raise ValueError("取号结果缺少邮箱或 mailId")
            parsed.append({"email": email, "mail_id": mail_id})
        if not parsed:
            raise ValueError("没有取到可用的邮箱")

        inserted = updated = 0
        superseded: list[int] = []
        now = _now()
        with self._lock:
            records = self._read()
            for item in parsed:
                account_id = self._id(item["email"])
                existing = records.get(account_id)
                previous_mail_id = (existing or {}).get("mail_id")
                if previous_mail_id and int(previous_mail_id) != item["mail_id"]:
                    superseded.append(int(previous_mail_id))
                record = existing or {
                    "id": account_id,
                    "email": item["email"],
                    "created_at": now,
                    "codex_status": "",
                    "codex_message": "",
                    "credential_path": None,
                }
                # A re-rented address starts over: any password / 2FA secret from
                # a previous attempt belongs to an account that no longer exists.
                for key in (
                    "password",
                    "client_id",
                    "refresh_token",
                    "code_url",
                    "totp_secret",
                    "import_material",
                    "register_message",
                ):
                    record.pop(key, None)
                record["source"] = _SMSBOWER_GMAIL
                record["mail_id"] = item["mail_id"]
                record["register_status"] = "pending"
                record["updated_at"] = now
                records[account_id] = record
                if existing:
                    updated += 1
                else:
                    inserted += 1
            self._write(records)
        return {
            "parsed": len(parsed),
            "inserted": inserted,
            "updated": updated,
            "invalid": 0,
            "superseded": superseded,
        }

    @staticmethod
    def _original_material(record: Mapping) -> str:
        """Return a re-importable line in the account's original source format.

        Plus 试用资格**不再**作为行尾的 ``----0/1`` 附在素材上——它由
        :meth:`export_original` 的段落标题（``----有试用资格----``）表达，
        导出的素材行保持干净的 ``email----密码----密钥``。
        """

        return MailboxStore._base_material(record)

    @staticmethod
    def _base_material(record: Mapping) -> str:
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
        if source == _SMSBOWER_GMAIL:
            # Only reached before注册 finished — once the account has both a
            # password and a 2FA secret the record is rewritten as password_totp
            # with an explicit ``import_material``. Emit whatever exists so a
            # half-finished batch still exports something usable.
            password = str(record.get("password") or "")
            return f"{email}----{password}" if password else email
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

    @staticmethod
    def _is_smsbower_origin(record: Mapping) -> bool:
        """注册成功后 source 会被改写成 password_totp，靠 origin_source 认出身。"""

        return _SMSBOWER_GMAIL in {
            str(record.get("source") or "").strip().lower(),
            str(record.get("origin_source") or "").strip().lower(),
        }

    def export_original(self, account_ids: list[str]) -> dict[str, list[str]]:
        """Group selected account materials by import source.

        smsbower-gmail 出身的账号单独成组，并按 **Plus 试用资格** 分段：
        导出的是干净的 ``email----密码----密钥``（去掉行尾的 ``----0/1`` 标识），
        资格信息改由段落标题表达，方便直接分堆使用。
        """

        normalized = [str(value or "").strip() for value in account_ids]
        if not normalized or any(not value for value in normalized):
            raise ValueError("请至少选择一个账号")
        with self._lock:
            records = self._read()
            missing = [value for value in normalized if value not in records]
            if missing:
                raise KeyError("所选账号不存在")
            grouped: dict[str, list[str]] = {}
            with_trial: list[str] = []
            without_trial: list[str] = []
            for account_id in normalized:
                record = records[account_id]
                if self._is_smsbower_origin(record):
                    # _base_material 不带 ----0/1 后缀，正是这里要的干净素材。
                    line = self._base_material(record)
                    if record.get("plus_trial") is True:
                        with_trial.append(line)
                    else:
                        without_trial.append(line)
                    continue
                source = str(record.get("source") or "unknown").strip().lower()
                grouped.setdefault(source, []).append(self._original_material(record))
            if with_trial or without_trial:
                lines: list[str] = []
                if with_trial:
                    lines.append("----有试用资格----")
                    lines.extend(with_trial)
                if without_trial:
                    if lines:
                        lines.append("")
                    lines.append("----无试用资格----")
                    lines.extend(without_trial)
                grouped[_SMSBOWER_GMAIL] = lines
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

    def update_registration(
        self,
        email: str,
        *,
        status: str,
        message: str = "",
        password: str | None = None,
        totp_secret: str | None = None,
        plus_trial: bool | None = None,
    ) -> bool:
        """Record 注册 progress for one rented smsbower address.

        Only the fields that are passed get written, so the password captured
        before the code step survives a later failure — the account may well
        exist by then, and losing its password would make it unreachable.

        Once both the password and the 2FA secret are known the record is
        rewritten as a plain ``password_totp`` account: its material now IS
        ``email----密码----密钥``, which every other pipeline mode and the export
        already understand. ``origin_source`` keeps the trail back to smsbower.
        """

        with self._lock:
            records = self._read()
            record = records.get(self._id(email))
            if record is None:
                return False
            record["register_status"] = str(status or "")
            record["register_message"] = str(message or "")
            if password is not None:
                record["password"] = str(password)
                # Also surfaced in the account list, like the OAuth signup path.
                record["signup_password"] = str(password)
            if totp_secret is not None:
                record["totp_secret"] = normalize_totp_secret(totp_secret)
            if plus_trial is not None:
                # 1 个月 Plus 免费资格，导出时追加成末列 ----0/1。
                record["plus_trial"] = bool(plus_trial)
            stored_password = str(record.get("password") or "")
            stored_secret = str(record.get("totp_secret") or "")
            if stored_password and stored_secret:
                record["origin_source"] = record.get("origin_source") or record.get("source")
                record["source"] = "password_totp"
                record["import_material"] = "----".join(
                    (str(record.get("email") or ""), stored_password, stored_secret)
                )
                record["register_status"] = "success"
            record["updated_at"] = _now()
            self._write(records)
            return True

    def update_manual_credentials(
        self,
        account_id: str,
        *,
        password: str | None = None,
        totp_secret: str | None = None,
        plus_trial: bool | None = None,
        register_status: str | None = None,
        codex_status: str | None = None,
    ) -> dict:
        """人工编辑一个注册出来的账号（密码 / 2FA 密钥 / Plus 资格 / 注册状态）。

        用途：自动开 2FA 失败（或人工在浏览器里自己开的）之后，把手抄回来的
        Base32 密钥补进记录里 —— 密码 + 密钥齐了，记录就会像注册成功一样自动改写
        成 `password_totp` 素材（`email----密码----密钥`），账号立刻可用。

        **空字符串 = 保持原值**（UI 上密钥框永远是空的，不这么定就会一保存把密钥
        清掉）。要清空得显式传 ``None`` 之外的哨兵——目前没有清空的需求，所以不做。
        密钥格式不对直接抛 ValueError：写进去一个手抄错的密钥，账号看着"就绪"其实
        每次登录都算错验证码，比直接报错难查得多。

        register_status 可以手动修正注册状态（pending / registered / success / failed），
        但不会覆盖"密码 + 密钥齐了自动改成 success"的逻辑。
        """

        new_password = str(password or "").strip()
        raw_secret = str(totp_secret or "").strip()
        new_secret = normalize_totp_secret(raw_secret) if raw_secret else ""
        new_register_status = str(register_status or "").strip()
        new_codex_status = str(codex_status or "").strip()
        with self._lock:
            records = self._read()
            record = records.get(str(account_id or ""))
            if record is None:
                raise ValueError("账号不存在或已删除")
            source = str(record.get("source") or "").strip().lower()
            origin = str(record.get("origin_source") or "").strip().lower()
            if _EDITABLE_SOURCES.isdisjoint({source, origin}):
                raise ValueError("只有 smsbower-gmail 或密码 + TOTP 2FA 类型的账号支持编辑")
            if new_password:
                record["password"] = new_password
                record["signup_password"] = new_password
            if new_secret:
                record["totp_secret"] = new_secret
            if plus_trial is not None:
                record["plus_trial"] = bool(plus_trial)
            if new_register_status:
                record["register_status"] = new_register_status
            if new_codex_status:
                record["codex_status"] = new_codex_status
                record["codex_message"] = (
                    "已手动标记为成功" if new_codex_status == "success" else "已手动标记为失败"
                )
            stored_password = str(record.get("password") or "")
            stored_secret = str(record.get("totp_secret") or "")
            if stored_password and stored_secret:
                # 和注册成功走同一条改写路径，导出格式因此完全一致。
                record["origin_source"] = record.get("origin_source") or record.get("source")
                record["source"] = "password_totp"
                record["import_material"] = "----".join(
                    (str(record.get("email") or ""), stored_password, stored_secret)
                )
                record["register_status"] = "success"
                record["register_message"] = "已手动补全密码和 2FA 密钥"
            record["updated_at"] = _now()
            self._write(records)
            return self._public(record)

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
