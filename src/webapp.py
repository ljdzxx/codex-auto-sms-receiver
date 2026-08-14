from __future__ import annotations

import base64
import ipaddress
import io
import json
import logging
import re
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, request, send_file

from .artifact_store import ArtifactStore, _redact_log_text
from .browser_bridge import BrowserBridgeTimeout, browser_bridge
from .browser_config_store import BrowserConfigStore
from .gcash_store import GcashTabStore
from .hero_catalog import HeroCatalog
from .hero_pricing import HeroPricingClient, HeroPricingError, filter_price_tiers
from .hero_sms import SMSBOWER_API_BASE
from .mailbox_store import MailboxStore
from .proxy_store import ProxyParseError, ProxyStore
from .proxy_tester import test_proxies
from .settings import Settings
from .sms_config import SmsConfigStore, normalize_hero_countries, normalize_price
from .smsbower_mail import (
    MAIL_STATUS_CANCEL,
    SmsbowerMailClient,
    SmsbowerMailError,
    SmsbowerMailOutOfStockError,
)
from .smsbower_mail_store import MAIL_DOMAIN, MAIL_SERVICE, SmsbowerMailConfigStore

_EXTENSION_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://")


class _ActivationStoreError(RuntimeError):
    """租到号却存不下来：号已经退回，消息里写清退了几个。"""

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_EXTENSION_FILE_BYTES = 24 * 1024 * 1024


def _is_loopback_host(host: str) -> bool:
    value = str(host or "").strip().lower().strip("[]")
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_extension_origin(origin: str) -> bool:
    value = str(origin or "").strip().lower()
    return any(value.startswith(prefix) for prefix in _EXTENSION_ORIGIN_PREFIXES)


def _safe_download_name(value: str) -> str:
    name = _CONTROL_CHARACTERS.sub("", Path(str(value or "")).name).strip().strip(". ")
    if not name:
        return "download.bin"
    if len(name) <= 180:
        return name
    suffix = Path(name).suffix[:32]
    stem = Path(name).stem[: max(1, 180 - len(suffix))]
    return f"{stem}{suffix}"


def create_app(
    settings: Settings,
    *,
    mailbox_store=None,
    codex_manager=None,
    sms_config_store=None,
    hero_catalog=None,
    hero_pricing=None,
    smsbower_pricing=None,
    artifact_store=None,
    smsbower_mail_store=None,
    smsbower_mail_client_factory=None,
    **_legacy,
) -> Flask:
    if not _is_loopback_host(settings.host):
        raise ValueError("未启用控制台登录，WEBUI_HOST 必须是本机回环地址")
    # 网页版控制台已移除：后端只提供 JSON API，UI 一律使用 Chrome 扩展侧边栏。
    app = Flask(__name__, template_folder=None, static_folder=None)
    app.config.update(
        MAX_CONTENT_LENGTH=48 * 1024 * 1024,
    )
    mailbox_store = mailbox_store or MailboxStore(settings.data_dir)
    sms_config_store = sms_config_store or SmsConfigStore(settings.project_root / ".env")
    hero_catalog = hero_catalog or HeroCatalog()
    artifact_store = artifact_store or ArtifactStore(settings.data_dir, settings.log_dir)
    gcash_tab_store = GcashTabStore(settings.data_dir)
    proxy_store = ProxyStore(settings.data_dir)
    browser_config_store = BrowserConfigStore(settings.data_dir)
    smsbower_mail_store = smsbower_mail_store or SmsbowerMailConfigStore(settings.data_dir)
    smsbower_mail_client_factory = smsbower_mail_client_factory or (
        lambda api_key: SmsbowerMailClient(api_key)
    )
    if codex_manager is None:
        from .codex_service import CodexJobManager

        codex_manager = CodexJobManager(settings, mailbox_store, proxy_store=proxy_store)

    def _task_observed(job):
        if not isinstance(job, dict):
            return ""
        return str(
            job.get("updated_at")
            or job.get("finished_at")
            or job.get("started_at")
            or job.get("created_at")
            or ""
        )

    def _safe_recent_task(job):
        """Expose task progress without leaking worker paths or protocol secrets."""

        if not isinstance(job, dict):
            return None
        allowed = (
            "id",
            "pipeline_id",
            "email",
            "status",
            "stage",
            "attempt",
            "max_attempts",
            "failure_code",
            "retryable",
            "next_retry_at",
            "created_at",
            "started_at",
            "finished_at",
            "has_log",
            "log_count",
            "has_credential",
        )
        public = {key: job.get(key) for key in allowed if key in job}
        public["updated_at"] = _task_observed(job)
        public["message"] = _redact_log_text(str(job.get("message") or ""))[:1000]
        return public

    def _account_rows(jobs=None):
        rows = mailbox_store.list_accounts()
        jobs = list(codex_manager.list_jobs() if jobs is None else jobs)
        latest_jobs = {}
        for job in jobs:
            if not isinstance(job, dict):
                continue
            key = str(job.get("email") or "").strip().casefold()
            if not key:
                continue
            observed = _task_observed(job)
            previous = latest_jobs.get(key)
            previous_observed = str((previous or {}).get("_observed") or "")
            if previous is None or observed >= previous_observed:
                latest_jobs[key] = {"_observed": observed, "job": job}
        credential_rows = (
            artifact_store.list_credentials()
            if callable(getattr(artifact_store, "list_credentials", None))
            else []
        )
        credentials_by_email = {}
        for item in credential_rows:
            key = str(item.get("email") or "").strip().casefold()
            if key and item.get("exportable") and key not in credentials_by_email:
                credentials_by_email[key] = item
        phone_lookup = getattr(artifact_store, "phone_verification_for_account", None)
        for row in rows:
            row["codex_message"] = _redact_log_text(
                str(row.get("codex_message") or "")
            )[:1000]
            email_key = str(row.get("email") or "").strip().casefold()
            credential = credentials_by_email.get(email_key)
            row["has_credential"] = bool(credential)
            row["credential_id"] = str((credential or {}).get("id") or "")
            row["credential_modified_at"] = (credential or {}).get("modified_at")
            row["credential_expired"] = (credential or {}).get("expired")
            if credential and not row.get("phone_number") and callable(phone_lookup):
                verified = phone_lookup(str(row.get("id") or "")) or {}
                row["phone_verified"] = bool(verified.get("phone_number"))
                row["phone_number"] = str(verified.get("phone_number") or "")
                row["phone_verified_at"] = verified.get("phone_verified_at")
            recent = latest_jobs.get(email_key)
            row["recent_task"] = _safe_recent_task((recent or {}).get("job"))
        return rows

    def _pipeline_overview():
        getter = getattr(codex_manager, "pipeline_overview", None)
        if callable(getter):
            return getter()
        return {
            "id": "",
            "status": "idle",
            "active": False,
            "concurrency": 1,
            "retry_limit": 0,
            "total": 0,
            "completed": 0,
            "progress": 0.0,
            "counts": {},
        }

    @app.after_request
    def _security_headers(response):
        origin = request.headers.get("Origin", "")
        if _is_extension_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "service": "codex-auto-sms-receiver"})

    @app.get("/api/extension/bootstrap")
    def extension_bootstrap():
        browser_bridge.mark_client_seen()
        return jsonify(
            {
                "ok": True,
                "backend_origin": f"http://{settings.host}:{settings.port}",
                "serial_only": True,
                "max_concurrency": 1,
                "save_file_max_bytes": _MAX_EXTENSION_FILE_BYTES,
                "browser_bridge_connected": browser_bridge.client_recently_seen(within_seconds=60),
                "cleanup_origins": [
                    "https://chatgpt.com",
                    "https://auth.openai.com",
                    "https://openai.com",
                    "https://platform.openai.com",
                ],
                "page_context_domains": [
                    "chatgpt.com",
                    "auth.openai.com",
                    "openai.com",
                    "platform.openai.com",
                ],
            }
        )

    @app.get("/api/browser-bridge/poll")
    def browser_bridge_poll():
        try:
            wait_timeout = float(request.args.get("wait") or 25)
        except ValueError:
            wait_timeout = 25.0
        browser_bridge.mark_client_seen()
        payload = browser_bridge.poll_next(wait_timeout=max(0.0, min(wait_timeout, 30.0)))
        return jsonify({"ok": True, "request": payload})

    @app.post("/api/browser-bridge/respond")
    def browser_bridge_respond():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        request_id = str(data.get("request_id") or "").strip()
        if not request_id:
            return jsonify({"ok": False, "error": "缺少 request_id"}), 400
        browser_bridge.mark_client_seen()
        if not browser_bridge.resolve(request_id, data.get("response") if isinstance(data.get("response"), dict) else {}):
            return jsonify({"ok": False, "error": "浏览器桥接请求不存在或已结束"}), 404
        return jsonify({"ok": True})

    @app.post("/api/extension/files/save")
    def extension_save_file():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        filename = _safe_download_name(str(data.get("filename") or "download.bin"))
        payload = str(data.get("content_base64") or "").strip()
        if not payload:
            return jsonify({"ok": False, "error": "缺少文件内容"}), 400
        try:
            content = base64.b64decode(payload, validate=True)
        except ValueError:
            return jsonify({"ok": False, "error": "文件内容不是有效 Base64"}), 400
        if len(content) > _MAX_EXTENSION_FILE_BYTES:
            return jsonify({"ok": False, "error": "文件超过后端保存大小限制"}), 413
        download_dir = settings.data_dir / "extension-downloads"
        download_dir.mkdir(parents=True, exist_ok=True)
        target_name = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}-{filename}"
        path = download_dir / target_name
        path.write_bytes(content)
        return jsonify(
            {
                "ok": True,
                "file": {
                    "id": target_name,
                    "name": filename,
                    "size": len(content),
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                    "path": str(path),
                },
            }
        )

    @app.get("/api/extension/debug/dom")
    def extension_debug_dom():
        browser_bridge.mark_client_seen()
        try:
            result = browser_bridge.request("page_action", {"action": "snapshot_dom"}, timeout=30.0)
        except BrowserBridgeTimeout as exc:
            return jsonify({"ok": False, "error": str(exc)}), 504
        if not isinstance(result, dict):
            return jsonify({"ok": False, "error": "浏览器桥返回了无效结果"}), 502
        status_code = 200 if result.get("ok", True) else 409
        return jsonify(result), status_code

    @app.post("/api/extension/debug/snapshot")
    def extension_debug_snapshot():
        """Persist a DOM snapshot the extension captured from a user-picked tab.

        The debug workspace binds a tab by id, so the payload is already scoped
        to one page; here we only validate it and archive it under ``logs/debug``
        where the artifact viewer can pick it up like any other ``*.log``.
        """
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        try:
            tab_id = int(data.get("tab_id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "缺少有效的 tab_id"}), 400
        if tab_id < 0:
            return jsonify({"ok": False, "error": "缺少有效的 tab_id"}), 400
        snapshot = data.get("snapshot")
        if not isinstance(snapshot, dict) or not snapshot:
            return jsonify({"ok": False, "error": "缺少快照内容"}), 400
        record = {
            "tab_id": tab_id,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            **snapshot,
        }
        try:
            text = json.dumps(record, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "快照内容无法序列化"}), 400
        payload_size = len(text.encode("utf-8"))
        if payload_size > _MAX_EXTENSION_FILE_BYTES:
            return jsonify({"ok": False, "error": "快照超过后端保存大小限制"}), 413
        target_dir = Path(settings.log_dir) / "debug"
        target_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = target_dir / f"{tab_id}-{stamp}-screenshot.log"
        # Two snapshots inside the same second must not overwrite each other.
        attempt = 1
        while path.exists():
            attempt += 1
            path = target_dir / f"{tab_id}-{stamp}-{attempt}-screenshot.log"
        path.write_text(text, encoding="utf-8")
        return jsonify(
            {
                "ok": True,
                "file": {
                    "name": path.name,
                    "relative_path": f"debug/{path.name}",
                    "size": payload_size,
                    "path": str(path),
                    "saved_at": record["saved_at"],
                },
            }
        )

    @app.get("/")
    def index():
        return jsonify(
            {
                "ok": True,
                "service": "codex-auto-sms-receiver",
                "ui": "chrome-extension",
                "hint": "网页控制台已移除，请安装并使用 chrome_plus_ver 扩展侧边栏操作",
            }
        )

    @app.get("/api/overview")
    def overview():
        jobs = codex_manager.list_jobs()
        return jsonify(
            {
                "ok": True,
                "browser_available": bool(settings.browser_executable),
                "browser_executable": str(settings.browser_executable or ""),
                "accounts": _account_rows(jobs),
                "codex": codex_manager.availability(),
                "runtime_config": codex_manager.runtime_config(),
                "codex_jobs": [
                    safe for job in jobs if (safe := _safe_recent_task(job)) is not None
                ],
                "pipeline": _pipeline_overview(),
            }
        )

    @app.post("/api/accounts/import")
    def import_accounts():
        data = request.get_json(silent=True) or {}
        try:
            result = mailbox_store.import_text(
                source=str(data.get("source") or ""),
                text=str(data.get("text") or ""),
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        return jsonify({"ok": True, **result})

    @app.get("/api/accounts")
    def list_accounts():
        return jsonify({"ok": True, "accounts": _account_rows()})

    @app.get("/api/notices")
    def list_notices():
        # 侧边栏用它把流水线里的静默阶段（尤其是每 5s 一次的取码轮询）变成提示。
        # after=-1 表示"我刚连上，只要游标别补历史"，避免一开面板就弹一串旧提示。
        from .notice_store import notices

        try:
            after = int(request.args.get("after", -1))
        except (TypeError, ValueError):
            after = -1
        return jsonify({"ok": True, **notices.since(after)})

    @app.get("/api/smsbower-mail-config")
    def get_smsbower_mail_config():
        return jsonify({"ok": True, "config": smsbower_mail_store.public()})

    @app.post("/api/smsbower-mail-config")
    def save_smsbower_mail_config():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        try:
            config = smsbower_mail_store.save(data)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "config": config})

    def _store_activations(client, acquired: list[dict]) -> dict:
        """Record rented mailboxes, handing back anything that cannot be stored."""

        try:
            result = mailbox_store.import_activations(acquired)
        except Exception as exc:
            # The mailboxes are already rented and billed. If they cannot be
            # recorded there is no way to reach them again, so hand them back
            # instead of silently paying for addresses nobody will ever use.
            released = sum(1 for item in acquired if client.release(item["mail_id"], MAIL_STATUS_CANCEL))
            logging.getLogger(__name__).warning(
                "[smsbower-gmail] 取号成功但入库失败，已退回 %d/%d 个：%s", released, len(acquired), exc
            )
            raise _ActivationStoreError(f"取号成功但保存失败，已退回 {released} 个：{exc}") from exc
        # Same address rented twice: the old activation id is no longer reachable
        # from any record, so give it back instead of leaving it billing.
        for stale_id in result.pop("superseded", []):
            client.release(stale_id, MAIL_STATUS_CANCEL)
        return result

    def _acquire_one_smsbower_gmail() -> str:
        """Rent exactly one gmail address, store it, and return it.

        取号+注册流水线每处理完一个账号才调一次这里：号一租下来就开始计费，
        提前把 N 个号全租好等于让排在后面的号白付租金。
        """

        config = smsbower_mail_store.get()
        if not config.get("api_key"):
            raise RuntimeError("请先保存 smsbower 邮箱 API Key")
        client = smsbower_mail_client_factory(config["api_key"])
        activation = client.acquire(
            service=MAIL_SERVICE,
            domain=MAIL_DOMAIN,
            max_price=config.get("max_price", ""),
        )
        _store_activations(client, [{"email": activation.email, "mail_id": activation.mail_id}])
        return str(activation.email)

    @app.post("/api/accounts/import-smsbower-gmail")
    def import_smsbower_gmail_accounts():
        data = request.get_json(silent=True) or {}
        try:
            count = int(data.get("count", 1))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "取号数量必须是整数"}), 400
        if count < 1:
            return jsonify({"ok": False, "error": "取号数量必须大于 0"}), 400
        config = smsbower_mail_store.get()
        if not config.get("api_key"):
            return jsonify({"ok": False, "error": "请先保存 smsbower 邮箱 API Key"}), 400

        client = smsbower_mail_client_factory(config["api_key"])
        acquired: list[dict] = []
        failure = ""
        for _ in range(count):
            try:
                activation = client.acquire(
                    service=MAIL_SERVICE,
                    domain=MAIL_DOMAIN,
                    max_price=config.get("max_price", ""),
                )
            except SmsbowerMailOutOfStockError as exc:
                failure = f"{exc}（已取到 {len(acquired)} 个）"
                break
            except SmsbowerMailError as exc:
                failure = str(exc)
                break
            acquired.append({"email": activation.email, "mail_id": activation.mail_id})
        if not acquired:
            return jsonify({"ok": False, "error": failure or "没有取到可用的邮箱"}), 400
        try:
            result = _store_activations(client, acquired)
        except _ActivationStoreError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        return jsonify({"ok": True, "acquired": len(acquired), "warning": failure, **result})

    @app.post("/api/accounts/acquire-register-smsbower-gmail")
    def acquire_and_register_smsbower_gmail():
        """取一个号 → 立刻注册它 → 再取下一个，直到取满 count 个。

        取号和注册合成一次操作：号一租下来就计费，先批量租号再排队注册会让
        排在后面的号一直付租金；同时也避免注册中断时留下一堆没人管的号。
        """

        data = request.get_json(silent=True) or {}
        if data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "必须确认该操作会真实消耗取号费用"}), 400
        try:
            count = int(data.get("count", 1))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "取号数量必须是整数"}), 400
        if count < 1:
            return jsonify({"ok": False, "error": "取号数量必须大于 0"}), 400
        if not smsbower_mail_store.get().get("api_key"):
            return jsonify({"ok": False, "error": "请先保存 smsbower 邮箱 API Key"}), 400
        starter = getattr(codex_manager, "start_batch", None)
        if not callable(starter):
            return jsonify({"ok": False, "error": "当前任务管理器不支持流水线"}), 501
        try:
            pipeline = starter(
                [],
                concurrency=1,
                retry_limit=data.get("retry_limit", 0),
                retry_backoff_seconds=data.get("retry_backoff_seconds", 30),
                mode="register",
                supplier=_acquire_one_smsbower_gmail,
                supply_count=count,
                # 取号失败（多半是库存空）等多久再试。codex_service 对 smsbower
                # 一无所知，所以间隔在这里从配置读出来传进去。
                supply_retry_seconds=smsbower_mail_store.get().get("supply_retry_seconds", 10),
                # 账号成功或失败收尾后，首次领取下一个账号前的独立间隔。
                next_account_interval_seconds=smsbower_mail_store.get().get(
                    "next_account_interval_seconds", 60
                ),
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        return jsonify({"ok": True, "count": count, "pipeline": pipeline}), 202

    @app.get("/api/sms-config")
    def get_sms_config():
        return jsonify({"ok": True, "config": sms_config_store.snapshot()})

    @app.get("/api/hero-sms/catalog")
    def get_hero_sms_catalog():
        catalog = hero_catalog.catalog()
        return jsonify({"ok": True, **catalog})

    def _hero_pricing_client(api_key: str):
        if hero_pricing is None:
            return HeroPricingClient(api_key)
        if hasattr(hero_pricing, "for_api_key"):
            return hero_pricing.for_api_key(api_key)
        if callable(hero_pricing) and not hasattr(hero_pricing, "prices"):
            return hero_pricing(api_key)
        return hero_pricing

    def _smsbower_pricing_client(api_key: str):
        # smsbower reuses the Hero pricing client pointed at its own host/label.
        if smsbower_pricing is None:
            return HeroPricingClient(
                api_key,
                api_base=SMSBOWER_API_BASE,
                provider_label="smsbower",
            )
        if hasattr(smsbower_pricing, "for_api_key"):
            return smsbower_pricing.for_api_key(api_key)
        if callable(smsbower_pricing) and not hasattr(smsbower_pricing, "balance"):
            return smsbower_pricing(api_key)
        return smsbower_pricing

    def _saved_hero_key() -> str:
        # This is deliberately read from the backend store. Request bodies and
        # query strings can never override or receive the saved API key.
        return sms_config_store.reveal_credential("hero")

    @app.get("/api/hero-sms/balance")
    def get_hero_sms_balance():
        api_key = _saved_hero_key()
        if not api_key:
            return jsonify({"ok": False, "error": "Hero SMS API Key 尚未配置"}), 409
        try:
            balance = _hero_pricing_client(api_key).balance()
        except HeroPricingError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "error": f"Hero SMS 余额查询失败（{type(exc).__name__}）",
                }
            ), 502
        return jsonify({"ok": True, "provider": "hero", "balance": balance})

    @app.get("/api/smsbower/balance")
    def get_smsbower_balance():
        # smsbower is a peer channel; its key is read from the backend store the
        # same way Hero's is, so request bodies can never override it.
        api_key = sms_config_store.reveal_credential("smsbower")
        if not api_key:
            return jsonify({"ok": False, "error": "smsbower API Key 尚未配置"}), 409
        try:
            balance = _smsbower_pricing_client(api_key).balance()
        except HeroPricingError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "error": f"smsbower 余额查询失败（{type(exc).__name__}）",
                }
            ), 502
        return jsonify({"ok": True, "provider": "smsbower", "balance": balance})

    @app.post("/api/debug/email-otp")
    def debug_email_otp():
        # Debug helper for the "调试" tab: read the latest email OTP for a locally
        # stored account, reusing the same mailbox providers the OAuth pipeline
        # uses. The extension drives the browser-side flow (session/sentinel);
        # only the mailbox read has to happen backend-side.
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip()
        if not email:
            return jsonify({"ok": False, "error": "缺少 email"}), 400
        try:
            after_ts = float(data.get("after_ts"))
        except (TypeError, ValueError):
            after_ts = 0.0
        if after_ts <= 0:
            after_ts = time.time() - 180
        account = mailbox_store.get_secret(email=email)
        if not account:
            return jsonify({"ok": False, "error": f"本机未找到账号 {email}，无法读取邮箱 OTP"}), 404
        source = str(account.get("source") or "").strip().lower()
        from .upstream_bridge import (
            _generic_api_otp_provider,
            _outlook_otp_provider,
            _wait_for_email_otp,
        )

        if source == "outlook":
            otp_provider, cleanup = _outlook_otp_provider(account)
        elif source in {"generic_api", "code_url"}:
            otp_provider, cleanup = _generic_api_otp_provider(account)
        else:
            return jsonify(
                {"ok": False, "error": f"账号来源 {source or '未知'} 不支持自动读取邮箱 OTP"}
            ), 400
        try:
            code = _wait_for_email_otp(
                logging.getLogger(__name__), otp_provider, email, after_ts=after_ts
            )
        except Exception as exc:  # surface as JSON for the debug tab
            return jsonify({"ok": False, "error": f"读取邮箱 OTP 失败：{exc}"}), 502
        finally:
            try:
                cleanup()
            except Exception:
                pass
        return jsonify({"ok": True, "code": str(code).strip()})

    @app.route("/api/hero-sms/prices", methods=["GET", "POST"])
    def get_hero_sms_prices():
        api_key = _saved_hero_key()
        if not api_key:
            return jsonify({"ok": False, "error": "Hero SMS API Key 尚未配置"}), 409

        data = request.get_json(silent=True) if request.method == "POST" else None
        data = data if isinstance(data, dict) else {}
        requested: object = data.get("countries", data.get("country"))
        if requested is None and request.method == "GET":
            repeated = request.args.getlist("country")
            requested = repeated or request.args.get("countries") or request.args.get("country")
        config = sms_config_store.snapshot()
        try:
            countries = normalize_hero_countries(
                requested,
                fallback=config.get("countries") or (config.get("country") or "10",),
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if not countries:
            return jsonify({"ok": False, "error": "至少需要 1 个 Hero SMS 国家"}), 400

        try:
            rows = _hero_pricing_client(api_key).prices(countries)
        except HeroPricingError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "error": f"Hero SMS 价格查询失败（{type(exc).__name__}）",
                }
            ), 502

        try:
            directory = hero_catalog.catalog()
            country_names = {
                str(item.get("id") or ""): {
                    "name": str(item.get("name") or ""),
                    "name_en": str(item.get("name_en") or ""),
                    "flag": str(item.get("flag") or "🌐"),
                }
                for item in directory.get("countries", [])
                if isinstance(item, dict)
            }
        except Exception:
            country_names = {}

        try:
            minimum = normalize_price(
                data.get("min_price", config.get("min_price") or ""),
                field="最低购买价",
            )
            maximum = normalize_price(
                data.get("max_price", config.get("max_price") or ""),
                field="价格上限",
            )
            preferred = normalize_price(
                data.get("preferred_price", config.get("preferred_price") or ""),
                field="指定价格档位",
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if minimum and maximum and Decimal(minimum) > Decimal(maximum):
            return jsonify({"ok": False, "error": "最低购买价不能高于价格上限"}), 400
        if preferred and minimum and Decimal(preferred) < Decimal(minimum):
            return jsonify({"ok": False, "error": "指定价格档位不能低于最低购买价"}), 400
        if preferred and maximum and Decimal(preferred) > Decimal(maximum):
            return jsonify({"ok": False, "error": "指定价格档位不能高于价格上限"}), 400
        acquire_priority = str(
            data.get("acquire_priority", config.get("acquire_priority") or "country")
        ).strip().lower()
        if acquire_priority not in {"country", "price", "price_high"}:
            return jsonify({"ok": False, "error": "拿号优先级格式不正确"}), 400
        for row in rows:
            eligible = filter_price_tiers(
                row.get("tiers") or [],
                min_price=minimum,
                max_price=maximum,
            )
            eligible_prices = {
                str(item.get("price") or "")
                for item in eligible
                if item.get("available")
            }
            for tier in row.get("tiers") or []:
                tier["eligible"] = str(tier.get("price") or "") in eligible_prices
            available_prices = [
                str(item.get("price") or "")
                for item in eligible
                if item.get("available") and str(item.get("price") or "")
            ]
            row["available_in_range"] = bool(available_prices)
            row["lowest_available_price"] = available_prices[0] if available_prices else None
            row.update(country_names.get(str(row.get("country") or ""), {}))

        return jsonify(
            {
                "ok": True,
                "provider": "hero",
                "service": {"code": "dr", "name": "OpenAI"},
                "filters": {
                    "min_price": minimum,
                    "max_price": maximum,
                    "preferred_price": preferred,
                    "acquire_priority": acquire_priority,
                },
                "countries": rows,
            }
        )

    @app.get("/api/artifacts")
    def list_artifacts():
        return jsonify({"ok": True, **artifact_store.overview()})

    @app.get("/api/artifacts/sms-stats")
    def sms_statistics():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "接码统计仅允许从本机监听的 WebUI 查看"}), 403
        try:
            result = artifact_store.sms_statistics()
        except OSError as exc:
            return jsonify(
                {"ok": False, "error": f"无法读取接码日志（{type(exc).__name__}）"}
            ), 500

        try:
            directory = hero_catalog.catalog()
            country_names = {
                str(item.get("id") or ""): {
                    "name": str(item.get("name") or ""),
                    "name_en": str(item.get("name_en") or ""),
                    "flag": str(item.get("flag") or "🌐"),
                }
                for item in directory.get("countries", [])
                if isinstance(item, dict)
            }
        except Exception:
            country_names = {}

        def with_country_name(row):
            enriched = dict(row) if isinstance(row, dict) else {}
            country_id = str(enriched.get("country_id") or "")
            names = country_names.get(country_id, {})
            enriched.update(
                {
                    "name": names.get("name") or (f"国家 {country_id}" if country_id else "未知国家"),
                    "name_en": names.get("name_en") or "",
                    "flag": names.get("flag") or "🌐",
                }
            )
            return enriched

        payload = dict(result) if isinstance(result, dict) else {}
        payload["countries"] = [
            with_country_name(row) for row in payload.get("countries", [])
        ]
        payload["records"] = [
            with_country_name(row) for row in payload.get("records", [])
        ]
        return jsonify({"ok": True, **payload})

    def _download_guard():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感文件仅允许从本机监听的 WebUI 下载"}), 403
        if str(request.args.get("confirmed") or "").lower() not in {"1", "true"}:
            return jsonify({"ok": False, "error": "下载前必须明确确认"}), 400
        return None

    @app.get("/api/artifacts/credentials/<artifact_id>/download")
    def download_credential(artifact_id: str):
        blocked = _download_guard()
        if blocked is not None:
            return blocked
        path = artifact_store.credential_file(artifact_id)
        if path is None:
            return jsonify({"ok": False, "error": "凭证文件不存在"}), 404
        return send_file(
            path,
            mimetype="application/json",
            as_attachment=True,
            download_name=path.name,
            conditional=False,
            etag=False,
            max_age=0,
        )

    @app.get("/api/accounts/<account_id>/credential/download")
    def download_account_credential(account_id: str):
        blocked = _download_guard()
        if blocked is not None:
            return blocked
        account = mailbox_store.get_secret(account_id=account_id)
        if account is None:
            return jsonify({"ok": False, "error": "账号不存在"}), 404
        credential = artifact_store.exportable_credential_for_email(
            str(account.get("email") or "")
        )
        if not credential:
            return jsonify({"ok": False, "error": "该账号没有可导出的 OAuth 凭证"}), 404
        path = artifact_store.exportable_credential_file(
            str(credential.get("id") or ""), expected_email=str(account.get("email") or "")
        )
        if path is None:
            return jsonify({"ok": False, "error": "该账号的 OAuth 凭证不可用"}), 404
        return send_file(
            path,
            mimetype="application/json",
            as_attachment=True,
            download_name=path.name,
            conditional=False,
            etag=False,
            max_age=0,
        )

    @app.get("/api/artifacts/logs/<artifact_id>/download")
    def download_log(artifact_id: str):
        blocked = _download_guard()
        if blocked is not None:
            return blocked
        path = artifact_store.log_file(artifact_id)
        if path is None:
            return jsonify({"ok": False, "error": "日志文件不存在"}), 404
        return send_file(
            path,
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=path.name,
            conditional=False,
            etag=False,
            max_age=0,
        )

    @app.get("/api/artifacts/logs/<artifact_id>/content")
    def view_log_content(artifact_id: str):
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "日志内容仅允许从本机监听的 WebUI 查看"}), 403
        try:
            offset = int(request.args.get("offset", "0"))
            limit = int(request.args.get("limit", "200"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "日志分页参数必须是整数"}), 400
        try:
            result = artifact_store.read_log_events(
                artifact_id,
                offset=offset,
                limit=limit,
                level=str(request.args.get("level") or "all"),
                query=str(request.args.get("q") or ""),
                order=str(request.args.get("order") or "desc"),
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        if result is None:
            return jsonify({"ok": False, "error": "日志文件不存在"}), 404
        return jsonify({"ok": True, **result})

    @app.get("/api/logs/timeline")
    def view_log_timeline():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "日志时间线仅允许从本机监听的 WebUI 查看"}), 403
        try:
            offset = int(request.args.get("offset", "0"))
            limit = int(request.args.get("limit", "100"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "日志分页参数必须是整数"}), 400
        reader = getattr(artifact_store, "read_log_timeline", None)
        if not callable(reader):
            return jsonify({"ok": False, "error": "当前日志存储不支持聚合时间线"}), 501
        account_emails = {
            str(row.get("id") or "").strip().lower(): str(row.get("email") or "")
            for row in mailbox_store.list_accounts()
            if isinstance(row, dict) and row.get("id")
        }
        try:
            result = reader(
                offset=offset,
                limit=limit,
                level=str(request.args.get("level") or "important"),
                query=str(request.args.get("q") or request.args.get("query") or ""),
                account_emails=account_emails,
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        jobs = [job for job in codex_manager.list_jobs() if isinstance(job, dict)]
        latest_job = max(jobs, key=_task_observed, default=None)
        result["recent_task"] = _safe_recent_task(latest_job)
        return jsonify({"ok": True, **result})

    def _zip_download(rows, *, filename: str):
        if not rows:
            return jsonify({"ok": False, "error": "没有可打包的文件"}), 404
        total_size = 0
        for path, _ in rows:
            try:
                total_size += path.stat().st_size
            except OSError:
                continue
        if total_size > 128 * 1024 * 1024:
            return jsonify({"ok": False, "error": "归档文件总量超过 128MB，请单独下载"}), 413
        # Keep small exports in memory, then transparently spill larger ZIPs
        # to a temporary file instead of retaining up to 128 MB in RAM.
        buffer = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        try:
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path, relative in rows:
                    try:
                        archive.write(path, arcname=relative)
                    except OSError:
                        continue
            buffer.seek(0)
            response = send_file(
                buffer,
                mimetype="application/zip",
                as_attachment=True,
                download_name=filename,
                conditional=False,
                etag=False,
                max_age=0,
            )
        except Exception:
            buffer.close()
            raise
        response.call_on_close(buffer.close)
        return response

    def _selected_credential_files(data) -> list[tuple[Path, str]]:
        if not isinstance(data, dict):
            raise ValueError("请提交 JSON 对象")
        if data.get("confirmed") is not True:
            raise ValueError("导出前必须明确确认")
        credential_ids = data.get("credential_ids", [])
        account_ids = data.get("account_ids", [])
        if not isinstance(credential_ids, list) or not isinstance(account_ids, list):
            raise ValueError("凭证和账号 ID 必须使用数组")
        if not credential_ids and not account_ids:
            raise ValueError("请至少选择一个凭证")
        if len(credential_ids) + len(account_ids) > 100:
            raise OverflowError("每次最多导出 100 个凭证")
        if any(not isinstance(value, str) or not value.strip() for value in credential_ids):
            raise ValueError("凭证 ID 格式无效")
        if any(not isinstance(value, str) or not value.strip() for value in account_ids):
            raise ValueError("账号 ID 格式无效")

        exportable = {
            str(item.get("id") or "").strip().lower(): item
            for item in artifact_store.list_credentials()
            if item.get("exportable") and item.get("id")
        }
        selected: dict[str, tuple[Path, str]] = {}
        for raw_id in credential_ids:
            artifact_id = raw_id.strip().lower()
            if artifact_id not in exportable:
                raise KeyError("所选凭证不存在或不可导出")
            path = artifact_store.exportable_credential_file(artifact_id)
            if path is None:
                raise KeyError("所选凭证不存在或不可导出")
            selected[str(path.resolve())] = (path, path.name)
        for raw_id in account_ids:
            account = mailbox_store.get_secret(account_id=raw_id.strip())
            if account is None:
                raise KeyError("所选账号不存在")
            email = str(account.get("email") or "")
            credential = artifact_store.exportable_credential_for_email(email)
            if not credential:
                raise KeyError("所选账号没有可导出的 OAuth 凭证")
            path = artifact_store.exportable_credential_file(
                str(credential.get("id") or ""), expected_email=email
            )
            if path is None:
                raise KeyError("所选账号的 OAuth 凭证不可用")
            selected[str(path.resolve())] = (path, path.name)
        return list(selected.values())

    def _selection_error(exc: Exception):
        if isinstance(exc, OverflowError):
            return jsonify({"ok": False, "error": str(exc)}), 413
        if isinstance(exc, KeyError):
            return jsonify({"ok": False, "error": str(exc).strip("'")}), 404
        return jsonify({"ok": False, "error": str(exc)}), 400

    def _sub2api_payload(rows: list[tuple[Path, str]]) -> dict:
        accounts = []
        for path, _ in rows:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError(f"凭证文件读取失败：{path.name}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"凭证文件格式无效：{path.name}")
            credentials = {}
            for source_key, target_key in (
                ("access_token", "access_token"),
                ("refresh_token", "refresh_token"),
                ("id_token", "id_token"),
                ("account_id", "chatgpt_account_id"),
                ("email", "email"),
                ("plan_type", "plan_type"),
            ):
                value = raw.get(source_key)
                if value is not None and str(value).strip():
                    credentials[target_key] = value
            expires_at = raw.get("expired") or raw.get("expires_at")
            if expires_at:
                credentials["expires_at"] = expires_at
            raw_type = str(raw.get("type") or "").strip().lower()
            if "plan_type" not in credentials and raw_type in {
                "free",
                "plus",
                "pro",
                "team",
                "business",
                "enterprise",
            }:
                credentials["plan_type"] = raw_type
            if not credentials.get("access_token") and not credentials.get("refresh_token"):
                raise ValueError(f"凭证缺少可用 OAuth Token：{path.name}")
            email = str(raw.get("email") or path.stem).strip()
            accounts.append(
                {
                    "name": email,
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": credentials,
                    "extra": {},
                    "concurrency": 1,
                    "priority": 50,
                }
            )
        return {
            "type": "sub2api-data",
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "proxies": [],
            "accounts": accounts,
        }

    @app.get("/api/artifacts/credentials.zip")
    def download_all_credentials():
        blocked = _download_guard()
        if blocked is not None:
            return blocked
        return _zip_download(
            artifact_store.exportable_credential_files(),
            filename="codex-credentials.zip",
        )

    @app.post("/api/artifacts/credentials/selected.zip")
    def download_selected_credentials():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感文件仅允许从本机监听的 WebUI 下载"}), 403
        try:
            rows = _selected_credential_files(request.get_json(silent=True))
        except (ValueError, KeyError, OverflowError) as exc:
            return _selection_error(exc)
        return _zip_download(rows, filename="codex-selected-credentials.zip")

    @app.post("/api/artifacts/credentials/selected/export")
    def export_selected_credentials():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感文件仅允许从本机监听的 WebUI 下载"}), 403
        data = request.get_json(silent=True)
        try:
            rows = _selected_credential_files(data)
        except (ValueError, KeyError, OverflowError) as exc:
            return _selection_error(exc)
        export_format = str((data or {}).get("format") or "codex_json").strip().lower()
        if export_format == "codex_json":
            return _zip_download(rows, filename="codex-selected-credentials.zip")
        if export_format != "sub2api":
            return jsonify({"ok": False, "error": "不支持的凭证导出格式"}), 400
        try:
            payload = _sub2api_payload(rows)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        return send_file(
            io.BytesIO(content),
            mimetype="application/json",
            as_attachment=True,
            download_name="sub2api-accounts.json",
            conditional=False,
            etag=False,
            max_age=0,
        )

    @app.delete("/api/artifacts/credentials/selected")
    def delete_selected_credentials():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感文件仅允许从本机 WebUI 管理"}), 403
        data = request.get_json(silent=True)
        try:
            rows = _selected_credential_files(data)
            ids_by_path = {}
            for item in artifact_store.list_credentials():
                if not item.get("exportable") or not item.get("id"):
                    continue
                credential_path = artifact_store.credential_file(str(item.get("id") or ""))
                if credential_path is not None:
                    ids_by_path[str(credential_path.resolve())] = str(item.get("id") or "")
            artifact_ids = [ids_by_path[str(path.resolve())] for path, _ in rows]
            deleted = artifact_store.delete_credentials(artifact_ids)
        except (ValueError, KeyError, OverflowError, OSError) as exc:
            return _selection_error(exc)
        return jsonify({"ok": True, "deleted": deleted})

    @app.get("/api/artifacts/logs.zip")
    def download_all_logs():
        blocked = _download_guard()
        if blocked is not None:
            return blocked
        return _zip_download(artifact_store.log_files(), filename="codex-logs.zip")

    @app.post("/api/sms-config")
    def save_sms_config():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感短信凭证仅允许在本机监听模式下保存"}), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        if any(
            str(job.get("status") or "") in {"queued", "running", "retry_wait"}
            for job in codex_manager.list_jobs()
        ):
            return jsonify({"ok": False, "error": "Codex OAuth 任务运行中，请结束后再修改短信配置"}), 409
        try:
            config = sms_config_store.save(data)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False, "error": f"无法写入 .env：{exc}"}), 500
        return jsonify(
            {
                "ok": True,
                "config": config,
                "codex": codex_manager.availability(),
                "runtime_config": codex_manager.runtime_config(),
            }
        )

    @app.post("/api/sms-config/reveal")
    def reveal_sms_credential():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "敏感短信凭证仅允许在本机监听模式下显示"}), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "必须明确确认显示凭证"}), 400
        provider = str(data.get("provider") or "hero").strip().lower() or "hero"
        try:
            credential = sms_config_store.reveal_credential(provider)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if not credential:
            label = "smsbower" if provider == "smsbower" else "Hero SMS"
            return jsonify({"ok": False, "error": f"{label} 尚未保存 API Key"}), 404
        return jsonify({"ok": True, "credential": credential})

    @app.post("/api/accounts/selected/export")
    def export_selected_accounts():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "账号素材仅允许从本机监听的 WebUI 下载"}), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "导出前必须明确确认"}), 400
        account_ids = data.get("account_ids", [])
        if not isinstance(account_ids, list) or not account_ids:
            return jsonify({"ok": False, "error": "请至少选择一个账号"}), 400
        if len(account_ids) > 500:
            return jsonify({"ok": False, "error": "每次最多导出 500 个账号"}), 413
        if any(not isinstance(value, str) or not value.strip() for value in account_ids):
            return jsonify({"ok": False, "error": "账号 ID 格式无效"}), 400
        try:
            grouped = mailbox_store.export_original(account_ids)
        except (ValueError, KeyError) as exc:
            return _selection_error(exc)
        buffer = tempfile.SpooledTemporaryFile(max_size=2 * 1024 * 1024, mode="w+b")
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for source, lines in grouped.items():
                content = ("\n".join(lines) + "\n").encode("utf-8")
                archive.writestr(f"{source}.txt", content)
            archive.writestr(
                "README.txt",
                "每个 TXT 文件均保持对应的原导入格式；在 WebUI 选择同名登录素材类型后可直接重新导入。\n".encode(
                    "utf-8"
                ),
            )
        buffer.seek(0)
        response = send_file(
            buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name="account-materials-original-format.zip",
            conditional=False,
            etag=False,
            max_age=0,
        )
        response.call_on_close(buffer.close)
        return response

    @app.get("/api/gcash/tabs")
    def get_gcash_tabs():
        return jsonify({"ok": True, "tabs": gcash_tab_store.get()})

    @app.post("/api/gcash/tabs")
    def save_gcash_tabs():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        try:
            saved = gcash_tab_store.save(
                login_tab_id=data.get("login_tab_id"),
                extract_tab_id=data.get("extract_tab_id"),
                login_tab_label=str(data.get("login_tab_label") or ""),
                extract_tab_label=str(data.get("extract_tab_label") or ""),
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "tabs": saved})

    @app.get("/api/browser-config")
    def get_browser_config():
        return jsonify({"ok": True, "config": browser_config_store.public()})

    @app.post("/api/browser-config")
    def save_browser_config():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        try:
            browser_config_store.save(data)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "config": browser_config_store.public()})

    @app.get("/api/proxies")
    def list_proxies():
        return jsonify({"ok": True, **proxy_store.state()})

    @app.post("/api/proxies")
    def add_proxies():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        try:
            result = proxy_store.add_many(str(data.get("text") or ""), str(data.get("label") or ""))
        except ProxyParseError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, **result})

    @app.post("/api/proxies/enabled")
    def set_proxy_pool_enabled():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
            return jsonify({"ok": False, "error": "请提交 enabled 布尔值"}), 400
        return jsonify({"ok": True, **proxy_store.set_enabled(data["enabled"])})

    @app.post("/api/proxies/<proxy_id>/enabled")
    def set_single_proxy_enabled(proxy_id: str):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
            return jsonify({"ok": False, "error": "请提交 enabled 布尔值"}), 400
        try:
            return jsonify({"ok": True, **proxy_store.set_proxy_enabled(proxy_id, data["enabled"])})
        except KeyError:
            return jsonify({"ok": False, "error": "代理不存在"}), 404

    @app.delete("/api/proxies/<proxy_id>")
    def delete_proxy(proxy_id: str):
        try:
            return jsonify({"ok": True, **proxy_store.delete(proxy_id)})
        except KeyError:
            return jsonify({"ok": False, "error": "代理不存在"}), 404

    @app.post("/api/proxies/test")
    def run_proxy_test():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        raw_ids = data.get("proxy_ids")
        if raw_ids is None:
            # No explicit selection = 一键测试 the whole pool.
            targets = [row["id"] for row in proxy_store.state()["proxies"]]
        elif isinstance(raw_ids, list):
            targets = [str(value).strip() for value in raw_ids if str(value or "").strip()]
        else:
            return jsonify({"ok": False, "error": "proxy_ids 必须是数组"}), 400
        if not targets:
            return jsonify({"ok": False, "error": "代理池为空"}), 400
        if len(targets) > 100:
            return jsonify({"ok": False, "error": "每次最多测试 100 条代理"}), 413
        records = [record for record in (proxy_store.get_raw(value) for value in targets) if record]
        if not records:
            return jsonify({"ok": False, "error": "所选代理不存在"}), 404
        for outcome in test_proxies(records):
            proxy_store.record_test(
                outcome.get("id") or "",
                ok=bool(outcome.get("ok")),
                ip=str(outcome.get("ip") or ""),
                location=str(outcome.get("location") or ""),
                latency_ms=outcome.get("latency_ms"),
                message=str(outcome.get("message") or ""),
                country_code=str(outcome.get("country_code") or ""),
                timezone=str(outcome.get("timezone") or ""),
            )
        return jsonify({"ok": True, "tested": len(records), **proxy_store.state()})

    @app.post("/api/accounts/gcash-export")
    def export_gcash_results():
        if not _is_loopback_host(settings.host):
            return jsonify({"ok": False, "error": "提炼结果仅允许从本机监听的 WebUI 下载"}), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "导出前必须明确确认"}), 400
        account_ids = data.get("account_ids", [])
        if not isinstance(account_ids, list) or not account_ids:
            return jsonify({"ok": False, "error": "请至少选择一个账号"}), 400
        if len(account_ids) > 500:
            return jsonify({"ok": False, "error": "每次最多导出 500 个账号"}), 413
        if any(not isinstance(value, str) or not value.strip() for value in account_ids):
            return jsonify({"ok": False, "error": "账号 ID 格式无效"}), 400
        try:
            grouped = mailbox_store.export_gcash(account_ids)
        except (ValueError, KeyError) as exc:
            return _selection_error(exc)
        success = grouped.get("success") or []
        failed = grouped.get("failed") or []
        if not success and not failed:
            return jsonify({"ok": False, "error": "所选账号里没有 gcash 提炼结果"}), 400
        sections = [
            "----提炼成功----",
            "\n".join(success),
            "",
            "----提炼失败----",
            "\n".join(failed),
            "",
        ]
        body = "\n".join(sections).encode("utf-8")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        response = send_file(
            io.BytesIO(body),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"gcash-extraction-{stamp}.txt",
            conditional=False,
            etag=False,
            max_age=0,
        )
        return response

    @app.delete("/api/accounts/selected")
    def delete_selected_accounts():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "删除前必须明确确认"}), 400
        account_ids = data.get("account_ids", [])
        if not isinstance(account_ids, list) or not account_ids:
            return jsonify({"ok": False, "error": "请至少选择一个账号"}), 400
        if len(account_ids) > 500:
            return jsonify({"ok": False, "error": "每次最多删除 500 个账号"}), 413
        accounts = []
        for account_id in account_ids:
            if not isinstance(account_id, str) or not account_id.strip():
                return jsonify({"ok": False, "error": "账号 ID 格式无效"}), 400
            account = mailbox_store.get_secret(account_id=account_id.strip())
            if account is None:
                return jsonify({"ok": False, "error": "所选账号不存在"}), 404
            accounts.append(account)
        active = getattr(codex_manager, "is_account_active", None)
        if callable(active) and any(active(str(account.get("email") or "")) for account in accounts):
            return jsonify({"ok": False, "error": "所选账号中有正在运行的任务"}), 409
        try:
            deleted = mailbox_store.delete_many(account_ids)
        except (ValueError, KeyError) as exc:
            return _selection_error(exc)
        return jsonify({"ok": True, "deleted": deleted})

    @app.delete("/api/accounts/<account_id>")
    def delete_account(account_id: str):
        account = mailbox_store.get_secret(account_id=account_id)
        if account is None:
            return jsonify({"ok": False, "error": "账号不存在"}), 404
        active = getattr(codex_manager, "is_account_active", None)
        if callable(active) and active(str(account.get("email") or "")):
            return jsonify({"ok": False, "error": "账号正在流水线中，暂时不能删除"}), 409
        if not mailbox_store.delete(account_id):
            return jsonify({"ok": False, "error": "账号不存在"}), 404
        return jsonify({"ok": True})

    @app.post("/api/accounts/<account_id>/credentials")
    def update_account_credentials(account_id: str):
        """人工补全一个注册账号的密码 / 2FA 密钥（自动开 2FA 失败后的补救入口）。

        密钥留空 = 保持原值：清单接口从不回传密钥，编辑框里永远是空的，不这么定
        就会"一保存把密钥清掉"。
        """

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        account = mailbox_store.get_secret(account_id=account_id)
        if account is None:
            return jsonify({"ok": False, "error": "账号不存在"}), 404
        active = getattr(codex_manager, "is_account_active", None)
        if callable(active) and active(str(account.get("email") or "")):
            return jsonify({"ok": False, "error": "账号正在流水线中，暂时不能编辑"}), 409
        plus_trial = data.get("plus_trial")
        if plus_trial is not None and not isinstance(plus_trial, bool):
            return jsonify({"ok": False, "error": "plus_trial 只能是 true / false"}), 400
        register_status = data.get("register_status")
        if register_status is not None and register_status not in ("pending", "registered", "success", "failed"):
            return jsonify({"ok": False, "error": "register_status 只能是 pending / registered / success / failed"}), 400
        codex_status = data.get("codex_status")
        if codex_status is not None and codex_status not in ("success", "failed"):
            return jsonify({"ok": False, "error": "codex_status 只能是 success / failed"}), 400
        try:
            row = mailbox_store.update_manual_credentials(
                account_id,
                password=data.get("password"),
                totp_secret=data.get("totp_secret"),
                plus_trial=plus_trial,
                register_status=register_status,
                codex_status=codex_status,
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "account": row})

    @app.post("/api/codex-pipeline")
    def start_codex_pipeline():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "必须确认流水线可能消耗邮箱 OTP 和短信号码"}), 400
        emails = data.get("emails")
        if not isinstance(emails, list):
            return jsonify({"ok": False, "error": "流水线账号列表格式不正确"}), 400
        starter = getattr(codex_manager, "start_batch", None)
        if not callable(starter):
            return jsonify({"ok": False, "error": "当前任务管理器不支持流水线"}), 501
        try:
            pipeline = starter(
                emails,
                concurrency=data.get("concurrency", 1),
                retry_limit=data.get("retry_limit", 0),
                retry_backoff_seconds=data.get("retry_backoff_seconds", 30),
                mode=str(data.get("mode") or "oauth"),
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        return jsonify({"ok": True, "pipeline": pipeline}), 202

    @app.post("/api/codex-pipeline/<pipeline_id>/stop")
    def stop_codex_pipeline(pipeline_id: str):
        stopper = getattr(codex_manager, "stop_pipeline", None)
        if not callable(stopper) or not stopper(pipeline_id):
            return jsonify({"ok": False, "error": "流水线不存在或已经结束"}), 404
        return jsonify({"ok": True, "pipeline": _pipeline_overview()})

    @app.post("/api/codex-pipeline/<pipeline_id>/pause")
    def pause_codex_pipeline(pipeline_id: str):
        pauser = getattr(codex_manager, "pause_pipeline", None)
        if not callable(pauser):
            return jsonify({"ok": False, "error": "当前任务管理器不支持暂停"}), 501
        if not pauser(pipeline_id):
            return jsonify({"ok": False, "error": "流水线不存在、已暂停或已结束"}), 409
        return jsonify({"ok": True, "pipeline": _pipeline_overview()})

    @app.post("/api/codex-pipeline/<pipeline_id>/resume")
    def resume_codex_pipeline(pipeline_id: str):
        resumer = getattr(codex_manager, "resume_pipeline", None)
        if not callable(resumer):
            return jsonify({"ok": False, "error": "当前任务管理器不支持继续"}), 501
        if not resumer(pipeline_id):
            return jsonify({"ok": False, "error": "流水线不存在、未暂停或已结束"}), 409
        return jsonify({"ok": True, "pipeline": _pipeline_overview()})

    @app.post("/api/codex-jobs")
    def start_codex_job():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip()
        if data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "必须确认该操作可能消耗邮箱 OTP 和短信号码"}), 400
        if not any(str(item.get("email") or "").lower() == email.lower() for item in mailbox_store.list_accounts()):
            return jsonify({"ok": False, "error": "请先导入该已有账号的登录素材"}), 400
        try:
            job = codex_manager.start(email)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
        return jsonify({"ok": True, "job": job}), 202

    @app.post("/api/codex-jobs/<job_id>/stop")
    def stop_codex_job(job_id: str):
        if not codex_manager.stop(job_id):
            return jsonify({"ok": False, "error": "任务不存在或已经结束"}), 404
        return jsonify({"ok": True})

    app.extensions["codex_manager"] = codex_manager
    app.extensions["mailbox_store"] = mailbox_store
    app.extensions["sms_config_store"] = sms_config_store
    app.extensions["hero_catalog"] = hero_catalog
    app.extensions["hero_pricing"] = hero_pricing
    app.extensions["smsbower_pricing"] = smsbower_pricing
    app.extensions["artifact_store"] = artifact_store
    return app
