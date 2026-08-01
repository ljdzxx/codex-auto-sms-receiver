from __future__ import annotations

import ipaddress
import tempfile
import zipfile
from decimal import Decimal
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from .artifact_store import ArtifactStore, _redact_log_text
from .hero_catalog import HeroCatalog
from .hero_pricing import HeroPricingClient, HeroPricingError, filter_price_tiers
from .mailbox_store import MailboxStore
from .settings import Settings
from .sms_config import SmsConfigStore, normalize_hero_countries, normalize_price


def _is_loopback_host(host: str) -> bool:
    value = str(host or "").strip().lower().strip("[]")
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def create_app(
    settings: Settings,
    *,
    mailbox_store=None,
    codex_manager=None,
    sms_config_store=None,
    hero_catalog=None,
    hero_pricing=None,
    artifact_store=None,
    **_legacy,
) -> Flask:
    if not _is_loopback_host(settings.host):
        raise ValueError("未启用控制台登录，WEBUI_HOST 必须是本机回环地址")
    app = Flask(
        __name__,
        template_folder=str(settings.project_root / "templates"),
        static_folder=None,
    )
    app.config.update(
        MAX_CONTENT_LENGTH=32 * 1024,
    )
    mailbox_store = mailbox_store or MailboxStore(settings.data_dir)
    sms_config_store = sms_config_store or SmsConfigStore(settings.project_root / ".env")
    hero_catalog = hero_catalog or HeroCatalog()
    artifact_store = artifact_store or ArtifactStore(settings.data_dir, settings.log_dir)
    if codex_manager is None:
        from .codex_service import CodexJobManager

        codex_manager = CodexJobManager(settings, mailbox_store)

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

    @app.route("/login", methods=["GET", "POST"])
    @app.route("/logout", methods=["GET", "POST"])
    def legacy_auth_redirect():
        return redirect(url_for("index"), code=303)

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "service": "codex-auto-sms-receiver"})

    @app.get("/")
    def index():
        return render_template("index.html")

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
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "请提交 JSON 对象"}), 400
        if data.get("confirmed") is not True:
            return jsonify({"ok": False, "error": "下载前必须明确确认"}), 400

        credential_ids = data.get("credential_ids", [])
        account_ids = data.get("account_ids", [])
        if not isinstance(credential_ids, list) or not isinstance(account_ids, list):
            return jsonify({"ok": False, "error": "凭证和账号 ID 必须使用数组"}), 400
        if not credential_ids and not account_ids:
            return jsonify({"ok": False, "error": "请至少选择一个凭证"}), 400
        if len(credential_ids) + len(account_ids) > 100:
            return jsonify({"ok": False, "error": "每次最多导出 100 个凭证"}), 413
        if any(not isinstance(value, str) or not value.strip() for value in credential_ids):
            return jsonify({"ok": False, "error": "凭证 ID 格式无效"}), 400
        if any(not isinstance(value, str) or not value.strip() for value in account_ids):
            return jsonify({"ok": False, "error": "账号 ID 格式无效"}), 400

        exportable = {
            str(item.get("id") or "").strip().lower(): item
            for item in artifact_store.list_credentials()
            if item.get("exportable") and item.get("id")
        }
        selected: dict[str, tuple[Path, str]] = {}

        for raw_id in credential_ids:
            artifact_id = raw_id.strip().lower()
            if artifact_id not in exportable:
                return jsonify({"ok": False, "error": "所选凭证不存在或不可导出"}), 404
            path = artifact_store.exportable_credential_file(artifact_id)
            if path is None:
                return jsonify({"ok": False, "error": "所选凭证不存在或不可导出"}), 404
            selected[str(path.resolve())] = (path, path.name)

        for raw_id in account_ids:
            account = mailbox_store.get_secret(account_id=raw_id.strip())
            if account is None:
                return jsonify({"ok": False, "error": "所选账号不存在"}), 404
            email = str(account.get("email") or "")
            credential = artifact_store.exportable_credential_for_email(email)
            if not credential:
                return jsonify({"ok": False, "error": "所选账号没有可导出的 OAuth 凭证"}), 404
            path = artifact_store.exportable_credential_file(
                str(credential.get("id") or ""), expected_email=email
            )
            if path is None:
                return jsonify({"ok": False, "error": "所选账号的 OAuth 凭证不可用"}), 404
            selected[str(path.resolve())] = (path, path.name)

        return _zip_download(
            list(selected.values()),
            filename="codex-selected-credentials.zip",
        )

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
        try:
            credential = sms_config_store.reveal_credential("hero")
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if not credential:
            return jsonify({"ok": False, "error": "Hero SMS 尚未保存 API Key"}), 404
        return jsonify({"ok": True, "credential": credential})

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
    app.extensions["artifact_store"] = artifact_store
    return app
