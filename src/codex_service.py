from __future__ import annotations

import importlib.util
import json
import logging
import queue
import os
import re
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .artifact_store import _redact_log_text
from .mailbox_store import MailboxStore
from .proxy_store import ProxyStore
from .settings import Settings
from .sms_config import normalize_hero_countries
from .upstream_location import resolve_upstream_root


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(0, seconds))).isoformat()


def _parse_time(value: Any) -> float:
    try:
        return datetime.fromisoformat(str(value or "").replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


_PHONE_ATTEMPT = re.compile(r"手机验证尝试\s+\d+\s*/\s*\d+.*?号码=\+?(\d{7,15})")


class CodexJobManager:
    """Persistent batch scheduler for existing-account Codex OAuth jobs."""

    _ACTIVE_JOBS = {"queued", "running", "retry_wait"}
    _TERMINAL_JOBS = {"success", "failed", "stopped", "deactivated", "skipped"}
    _ACTIVE_PIPELINES = {"queued", "running", "paused", "stopping"}
    _MAX_CONCURRENCY = 1
    _MAX_RETRY_LIMIT = 99
    _MAX_BATCH_SIZE = 200
    # 主状态文件里保留多少条 job，更早的挪进 data/pipeline-archive/{YYYY-MM}.json。
    # 这个文件每次派发、每个结果都要全量重写，越大越容易撞 os.replace 的句柄冲突，
    # 所以它必须有上界。取 200 是因为 list_jobs() 本来就只回最近 500 条——界面能
    # 看到的历史几乎不受影响，而文件从 875 KB 降到 250 KB 上下。
    _RETAINED_JOBS = 200

    def __init__(self, settings: Settings, mailbox_store: MailboxStore, proxy_store=None):
        self.settings = settings
        self.mailbox_store = mailbox_store
        self.upstream_root = resolve_upstream_root(settings.project_root)
        self._jobs: dict[str, dict[str, Any]] = {}
        self._pipelines: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._data_dir = Path(getattr(settings, "data_dir", mailbox_store.data_dir))
        # Shared with the WebUI instance so the round-robin cursor and the pool
        # edits stay consistent; created here when the manager is built stand-alone.
        self.proxy_store = proxy_store or ProxyStore(self._data_dir)
        self._log_dir = Path(getattr(settings, "log_dir", settings.project_root / "logs"))
        self._state_path = self._data_dir / "pipeline-state.json"
        self._task_queue = None
        self._result_queue = None
        self._workers: list[Any] = []
        # Per-job cancellation flags, keyed by job id. A running worker thread
        # cannot be force-killed in Python, so long manual waits (gcash 扫码)
        # cooperatively poll this Event to exit promptly when the user stops.
        # Kept OUT of the job dict because that dict is JSON-persisted/deepcopied.
        self._cancel_events: dict[str, threading.Event] = {}
        self._load_state()
        self._recover_interrupted()
        # 启动时收敛一次：服务重启是最安全的归档时机（没有任何流水线在跑），
        # 也让存量历史不必等到下一次开工才被清理。
        with self._lock:
            if self._archive_old_state_locked():
                self._persist_locked()

    def availability(self) -> dict:
        if not (self.upstream_root / "core" / "codex_oauth.py").is_file():
            return {"available": False, "reason": "未找到原项目 core/codex_oauth.py"}
        missing = [name for name in ("curl_cffi", "Crypto", "pyotp") if importlib.util.find_spec(name) is None]
        if missing:
            return {"available": False, "reason": "缺少依赖：" + ", ".join(missing)}
        driver = (os.getenv("CODEX_OAUTH_DRIVER", "protocol") or "protocol").strip().lower()
        auth_source = (os.getenv("CODEX_AUTH_URL_SOURCE", "local") or "local").strip().lower()
        if driver not in {"protocol", "api", "http"}:
            return {"available": False, "reason": "此独立项目仅支持 CODEX_OAUTH_DRIVER=protocol"}
        if auth_source == "cpa" and not os.getenv("CPA_MANAGEMENT_KEY", "").strip():
            return {"available": False, "reason": "CPA 模式缺少 CPA_MANAGEMENT_KEY"}
        if not os.getenv("HERO_SMS_API_KEY", "").strip():
            return {"available": False, "reason": "Hero SMS 缺少 HERO_SMS_API_KEY"}
        try:
            countries = normalize_hero_countries(os.getenv("HERO_SMS_COUNTRIES", ""))
        except ValueError:
            countries = []
        if not countries:
            return {"available": False, "reason": "Hero SMS 至少需要选择 1 个国家"}
        return {"available": True, "reason": ""}

    def runtime_config(self) -> dict:
        return {
            "driver": "protocol",
            "auth_source": os.getenv("CODEX_AUTH_URL_SOURCE", "local") or "local",
            "sms_provider": "hero",
            "outlook_fetch_mode": os.getenv("OUTLOOK_FETCH_MODE", "direct") or "direct",
            "pipeline_max_concurrency": self._MAX_CONCURRENCY,
            "pipeline_max_retries": self._MAX_RETRY_LIMIT,
        }

    @staticmethod
    def _otp_ready(mailbox: dict[str, Any]) -> bool:
        if mailbox.get("source") in {"generic_api", "code_url"}:
            return bool(str(mailbox.get("code_url") or "").strip())
        if mailbox.get("source") in {"password_totp", "smsbower_gmail"}:
            # A freshly rented smsbower mailbox has neither yet — it only becomes
            # runnable after the 注册 flow writes the password + 2FA secret.
            return bool(
                str(mailbox.get("password") or "").strip()
                and str(mailbox.get("totp_secret") or "").strip()
            )
        return bool(str(mailbox.get("client_id") or "").strip() and str(mailbox.get("refresh_token") or "").strip())

    def _load_state(self) -> None:
        if not self._state_path.is_file():
            return
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(payload, dict):
            return
        jobs = payload.get("jobs")
        pipelines = payload.get("pipelines")
        if isinstance(jobs, dict):
            self._jobs = {str(key): value for key, value in jobs.items() if isinstance(value, dict)}
        if isinstance(pipelines, dict):
            self._pipelines = {
                str(key): value for key, value in pipelines.items() if isinstance(value, dict)
            }

    def _persist_locked(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        temporary = self._data_dir / f".{self._state_path.name}.{uuid.uuid4().hex}.tmp"
        payload = {"version": 1, "pipelines": self._pipelines, "jobs": self._jobs}
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            # Windows: os.replace raises PermissionError while ANY other handle
            # (antivirus scan, a sync client, a backup job) has the target open.
            # That window is not small — this file is rewritten in full on every
            # dispatch and every result — so retry briefly before giving up.
            for attempt in range(6):
                try:
                    os.replace(temporary, self._state_path)
                    return
                except PermissionError:
                    if attempt == 5:
                        raise
                    time.sleep(0.15 * (attempt + 1))
        except Exception as exc:  # noqa: BLE001 - persistence must never stop the pipeline
            # 落盘失败绝不能升级成"流水线停摆"：内存里的状态才是权威，丢掉的只是
            # 重启后的可恢复性。以前这个异常直接冒到 _run_pipeline 的 while 循环
            # （那里没有 try），调度线程当场死亡 → job 永远停在 running、inflight
            # 永不清空 → 不再取号也不再收工，表现为"整条流水线卡死"，而现场只留下
            # 一个写了一半的 .tmp 文件（实测 2026-08-13 09:51:55，跑到第 15 个账号）。
            logging.getLogger(__name__).warning(
                "流水线状态落盘失败，内存状态仍然有效，流水线继续：%s", exc
            )
        finally:
            # 失败时别把半成品留在 data/ 下（成功路径上它已经被 replace 掉了）。
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _archive_dir(self) -> Path:
        return self._data_dir / "pipeline-archive"

    def _append_archive(
        self, pipelines: dict[str, dict[str, Any]], jobs: dict[str, dict[str, Any]]
    ) -> bool:
        """Merge these records into data/pipeline-archive/{YYYY-MM}.json.

        Returns False (and drops nothing) when the archive cannot be written —
        a big state file is annoying, losing history is not acceptable.
        """

        archive_dir = self._archive_dir()
        path = archive_dir / f"{datetime.now(timezone.utc).strftime('%Y-%m')}.json"
        temporary = archive_dir / f".{path.name}.{uuid.uuid4().hex}.tmp"
        try:
            archive_dir.mkdir(parents=True, exist_ok=True)
            merged: dict[str, dict[str, Any]] = {"pipelines": {}, "jobs": {}}
            if path.is_file():
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    for key in ("pipelines", "jobs"):
                        value = loaded.get(key)
                        if isinstance(value, dict):
                            merged[key] = {
                                str(item_id): item
                                for item_id, item in value.items()
                                if isinstance(item, dict)
                            }
            merged["pipelines"].update(pipelines)
            merged["jobs"].update(jobs)
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump({"version": 1, **merged}, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            return True
        except Exception as exc:  # noqa: BLE001 - archiving is best-effort
            logging.getLogger(__name__).warning("流水线历史归档失败，本轮不清理：%s", exc)
            return False
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _archive_old_state_locked(self) -> bool:
        """把陈旧的 job / pipeline 挪进按月归档文件，让主状态文件保持小。

        `pipeline-state.json` 在**每次派发和每个结果**上都要全量重写，而 job 只增
        不减（实测跑到 657 条 / 875 KB）。文件越大、写得越频，越容易撞上 Windows
        的 `os.replace` 句柄冲突——2026-08-13 调度线程猝死就是这么来的。

        活跃流水线和活跃 job 一条都不动；归档只发生在启动时和新建流水线时，
        绝不在派发/收结果的热路径上。
        """

        if len(self._jobs) <= self._RETAINED_JOBS:
            return False
        active_pipelines = {
            str(pipeline_id)
            for pipeline_id, item in self._pipelines.items()
            if str(item.get("status") or "") in self._ACTIVE_PIPELINES
        }
        # 还在跑的东西无条件保留，其余按创建时间留最近的。
        keep = {
            job_id
            for job_id, job in self._jobs.items()
            if str(job.get("pipeline_id") or "") in active_pipelines
            or str(job.get("status") or "") in self._ACTIVE_JOBS
        }
        ordered = sorted(
            (job_id for job_id in self._jobs if job_id not in keep),
            key=lambda job_id: str(self._jobs[job_id].get("created_at") or ""),
            reverse=True,
        )
        keep.update(ordered[: max(0, self._RETAINED_JOBS - len(keep))])
        drop_jobs = {
            job_id: job for job_id, job in self._jobs.items() if job_id not in keep
        }
        if not drop_jobs:
            return False
        # 一条 job 都没留下的流水线跟着归档，别在主文件里留一堆空壳。
        drop_pipelines = {
            pipeline_id: pipeline
            for pipeline_id, pipeline in self._pipelines.items()
            if pipeline_id not in active_pipelines
            and (pipeline.get("job_ids") or [])
            and all(str(job_id) in drop_jobs for job_id in pipeline.get("job_ids") or [])
        }
        if not self._append_archive(drop_pipelines, drop_jobs):
            return False
        for job_id in drop_jobs:
            self._jobs.pop(job_id, None)
        for pipeline_id in drop_pipelines:
            self._pipelines.pop(pipeline_id, None)
        logging.getLogger(__name__).info(
            "流水线历史已归档：移出 %d 条任务 / %d 条流水线，主状态文件保留 %d 条任务",
            len(drop_jobs),
            len(drop_pipelines),
            len(self._jobs),
        )
        return True

    def _recover_interrupted(self) -> None:
        changed = False
        with self._lock:
            for job in self._jobs.values():
                if str(job.get("status") or "") in self._ACTIVE_JOBS:
                    job.update(
                        status="failed",
                        stage="服务已重启",
                        message="服务重启中断了上一次任务，可重新加入流水线",
                        failure_code="service_restarted",
                        retryable=False,
                        next_retry_at=None,
                        finished_at=_now(),
                    )
                    changed = True
            for pipeline in self._pipelines.values():
                if str(pipeline.get("status") or "") in self._ACTIVE_PIPELINES:
                    # 取号+注册的 supplier 是内存里的闭包，重启后拿不回来，
                    # 剩余的取号计划一并作废，别让 UI 一直显示"还差几个"。
                    pipeline.update(status="interrupted", finished_at=_now(), supply_remaining=0)
                    changed = True
            if changed:
                self._persist_locked()
        if changed:
            for job in self._jobs.values():
                if job.get("failure_code") == "service_restarted":
                    self.mailbox_store.update_codex(
                        str(job.get("email") or ""),
                        status="failed",
                        message="服务重启中断了上一次任务",
                    )

    def _public_job(self, item: dict) -> dict:
        row = deepcopy(item)
        current_log = row.pop("log_path", None)
        log_paths = row.pop("log_paths", [])
        credential_path = row.pop("credential_path", None)
        candidates = list(log_paths) if isinstance(log_paths, list) else []
        if current_log:
            candidates.append(current_log)
        existing_logs: set[str] = set()
        try:
            log_root = self._log_dir.resolve()
        except OSError:
            log_root = self._log_dir
        for value in candidates:
            try:
                resolved = Path(str(value or "")).resolve(strict=True)
                resolved.relative_to(log_root)
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                existing_logs.add(str(resolved))
        row["has_log"] = bool(existing_logs)
        row["log_count"] = len(existing_logs)
        row["has_credential"] = bool(credential_path)
        row["message"] = _redact_log_text(str(row.get("message") or ""))[:500]
        return row

    def list_jobs(self) -> list[dict]:
        with self._lock:
            rows = [self._public_job(item) for item in self._jobs.values()]
        rows.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return rows[:500]

    def _pipeline_public_locked(self, pipeline: dict[str, Any]) -> dict[str, Any]:
        job_ids = [str(value) for value in pipeline.get("job_ids") or []]
        jobs = [self._jobs[job_id] for job_id in job_ids if job_id in self._jobs]
        count_names = ("queued", "running", "retry_wait", "success", "failed", "stopped", "deactivated", "skipped")
        counts = {name: sum(1 for job in jobs if job.get("status") == name) for name in count_names}
        terminal = sum(counts[name] for name in self._TERMINAL_JOBS)
        # 取号+注册的账号是一个一个租来的：还没租到的那些也要算进总数，
        # 否则进度会先显示 1/1 再跳成 1/2，看着像重新开始。
        pending_supply = max(0, int(pipeline.get("supply_remaining") or 0))
        total = len(jobs) + pending_supply
        public = {key: deepcopy(value) for key, value in pipeline.items() if key != "job_ids"}
        public.update(
            {
                "total": total,
                "counts": counts,
                "completed": terminal,
                "progress": round((terminal / total) * 100, 1) if total else 0.0,
                "active": str(pipeline.get("status") or "") in self._ACTIVE_PIPELINES,
            }
        )
        return public

    def pipeline_overview(self, pipeline_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            selected = self._pipelines.get(str(pipeline_id or "")) if pipeline_id else None
            if selected is None:
                active = [
                    item
                    for item in self._pipelines.values()
                    if str(item.get("status") or "") in self._ACTIVE_PIPELINES
                ]
                candidates = active or list(self._pipelines.values())
                selected = max(candidates, key=lambda item: str(item.get("created_at") or "")) if candidates else None
            if selected is None:
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
            return self._pipeline_public_locked(selected)

    def _has_active_pipeline_locked(self) -> bool:
        return any(
            str(item.get("status") or "") in self._ACTIVE_PIPELINES
            for item in self._pipelines.values()
        )

    def start(self, email: str) -> dict:
        pipeline = self.start_batch([email], concurrency=1, retry_limit=0)
        pipeline_id = str(pipeline["id"])
        with self._lock:
            job = next(item for item in self._jobs.values() if item.get("pipeline_id") == pipeline_id)
            return self._public_job(job)

    def _prepare_mailbox(
        self,
        email: str,
        *,
        export_session: bool = False,
        login_only: bool = False,
        gcash_extract: bool = False,
        register_account: bool = False,
        gcash_tabs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Load one account and stamp it with the flags this run needs."""

        mailbox = self.mailbox_store.get_secret(email=email)
        if mailbox is None:
            raise ValueError(f"账号未导入：{email}")
        if register_account:
            # These accounts have no login material yet — that is the whole
            # point of registering them — so _otp_ready must not gate them.
            if str(mailbox.get("source") or "").strip().lower() != "smsbower_gmail":
                raise ValueError(f"只有 smsbower-gmail 取号的账号可以注册：{email}")
            if not str(mailbox.get("mail_id") or "").strip():
                raise ValueError(f"账号缺少 smsbower 活动 id，无法取码：{email}")
        elif not self._otp_ready(mailbox):
            raise ValueError(f"邮箱 OTP 配置未就绪：{email}")
        # Round-robin the proxy pool per account: every account in the batch
        # takes the next enabled proxy, and the browser applies it before the
        # first navigation. Returns None when the pool is off/empty, which
        # means "clear any proxy and use the direct connection".
        proxy = ProxyStore.browser_config(self.proxy_store.next_for_account())
        if proxy:
            mailbox = {**mailbox, "proxy": proxy}
        if export_session:
            # Signals the worker to also capture chatgpt.com/api/auth/session
            # after login and save it under data/codex_sessions/{date}/.
            mailbox = {**mailbox, "export_session": True}
        elif login_only:
            # Signals the worker to stop right after a successful login.
            mailbox = {**mailbox, "login_only": True}
        elif gcash_extract:
            # Carries the operator's tab binding into the worker, which has
            # no access to the extension UI that made the choice.
            tabs = gcash_tabs or {}
            mailbox = {
                **mailbox,
                "gcash_extract": True,
                "gcash_login_tab_id": int(tabs["login_tab_id"]),
                "gcash_extract_tab_id": int(tabs["extract_tab_id"]),
            }
        elif register_account:
            mailbox = {**mailbox, "register_account": True}
        return mailbox

    def start_batch(
        self,
        emails: Iterable[str],
        *,
        concurrency: int = 1,
        retry_limit: int = 0,
        retry_backoff_seconds: int = 30,
        mode: str = "oauth",
        supplier: Callable[[], str] | None = None,
        supply_count: int = 0,
        supply_retry_seconds: int = 10,
        next_account_interval_seconds: int = 60,
    ) -> dict[str, Any]:
        normalized_mode = str(mode or "oauth").strip().lower()
        export_session = normalized_mode == "session"
        # "仅登录"：只把选中的账号登录进 chatgpt.com，不导出 Session、不走 OAuth。
        login_only = normalized_mode == "login"
        # "gcash 提炼"：登录 → accessToken → 153 提炼 → 付款链接 → 等待扫码。
        gcash_extract = normalized_mode == "gcash"
        # "smsbower-gmail 注册"：给取号得到的地址建号、设密码、过邮箱验证码。
        register_account = normalized_mode == "register"
        gcash_tabs: dict[str, Any] = {}
        if gcash_extract:
            from .gcash_store import GcashTabStore

            gcash_tabs = GcashTabStore(self._data_dir).get()
            if gcash_tabs.get("login_tab_id") is None or gcash_tabs.get("extract_tab_id") is None:
                raise ValueError("请先在插件「调试」页绑定「ChatGPT登录」和「153提炼」两个标签页并保存")
        try:
            concurrency = int(concurrency)
            retry_limit = int(retry_limit)
            retry_backoff_seconds = int(retry_backoff_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("流水线并发和重试参数必须是整数") from exc
        if concurrency < 1:
            raise ValueError(f"任务并发必须在 1 - {self._MAX_CONCURRENCY} 之间")
        concurrency = 1
        if retry_limit < 0 or retry_limit > self._MAX_RETRY_LIMIT:
            raise ValueError(f"失败重试必须在 0 - {self._MAX_RETRY_LIMIT} 之间")
        if retry_backoff_seconds < 5 or retry_backoff_seconds > 600:
            raise ValueError("重试间隔必须在 5 - 600 秒之间")

        normalized: list[str] = []
        seen: set[str] = set()
        for email in emails:
            value = str(email or "").strip()
            key = value.casefold()
            if value and key not in seen:
                normalized.append(value)
                seen.add(key)
        if not normalized and supplier is None:
            raise ValueError("请至少选择 1 个账号")
        if len(normalized) > self._MAX_BATCH_SIZE:
            raise ValueError(f"单批最多处理 {self._MAX_BATCH_SIZE} 个账号")
        if login_only and len(normalized) != 1:
            raise ValueError("仅登录模式一次只能选择 1 个账号")
        # 取号+注册：账号是一个一个租来的，所以流水线开跑时清单可能是空的，由
        # supplier 在每个账号收尾后再租下一个（详见 _supply_next）。
        if supplier is not None:
            if not register_account:
                raise ValueError("只有注册模式支持边取号边处理")
            try:
                supply_count = int(supply_count)
            except (TypeError, ValueError) as exc:
                raise ValueError("取号数量必须是整数") from exc
            if supply_count < 1:
                raise ValueError("取号数量必须大于 0")
        else:
            supply_count = 0
        # 注册是批量操作（租一批号就是为了批量建号），不限账号数；并发已在上面
        # 强制钳到 1，共享同一个浏览器时账号之间靠 _bridge_cleanup() 顺序清理。
        availability = self.availability()
        if not availability["available"]:
            raise RuntimeError(availability["reason"])

        mailboxes: list[dict[str, Any]] = [
            self._prepare_mailbox(
                email,
                export_session=export_session,
                login_only=login_only,
                gcash_extract=gcash_extract,
                register_account=register_account,
                gcash_tabs=gcash_tabs,
            )
            for email in normalized
        ]

        self._ensure_workers(1)
        pipeline_id = uuid.uuid4().hex
        created_at = _now()
        job_mailboxes: dict[str, dict[str, Any]] = {}
        with self._lock:
            if self._has_active_pipeline_locked():
                raise RuntimeError("已有流水线正在运行")
            # 开工前收敛一次，别让这一批的每次落盘都背着全部历史。
            self._archive_old_state_locked()
            job_ids: list[str] = []
            for mailbox in mailboxes:
                job_id = self._new_job_locked(pipeline_id, mailbox, retry_limit, created_at)
                job_ids.append(job_id)
                job_mailboxes[job_id] = mailbox
            self._pipelines[pipeline_id] = {
                "id": pipeline_id,
                "status": "queued",
                "mode": normalized_mode or "oauth",
                "concurrency": concurrency,
                "retry_limit": retry_limit,
                "retry_backoff_seconds": retry_backoff_seconds,
                "pause_requested": False,
                "stop_requested": False,
                "created_at": created_at,
                "started_at": None,
                "paused_at": None,
                "resumed_at": None,
                "finished_at": None,
                "job_ids": job_ids,
                # 取号+注册专用：还欠多少个号没租、已经租到几个、租号失败的原因。
                "supply_total": supply_count,
                "supply_remaining": supply_count,
                "supply_acquired": 0,
                "supply_error": "",
                # 取号失败只推迟、不收工（见 _supply_next）。
                "supply_retry_seconds": max(1, min(600, int(supply_retry_seconds or 10))),
                "supply_failures": 0,
                "supply_retry_at": None,
                "next_account_interval_seconds": max(
                    0, min(3600, int(next_account_interval_seconds or 0))
                ),
                "next_supply_at": None,
            }
            self._persist_locked()
            public = self._pipeline_public_locked(self._pipelines[pipeline_id])

        threading.Thread(
            target=self._run_pipeline,
            args=(pipeline_id, job_mailboxes, supplier),
            name=f"codex-pipeline-{pipeline_id[:8]}",
            daemon=True,
        ).start()
        return public

    def _new_job_locked(
        self,
        pipeline_id: str,
        mailbox: dict[str, Any],
        retry_limit: int,
        created_at: str,
    ) -> str:
        job_id = uuid.uuid4().hex
        self._jobs[job_id] = {
            "id": job_id,
            "pipeline_id": pipeline_id,
            "account_id": mailbox.get("id"),
            "email": mailbox.get("email"),
            "source": mailbox.get("source"),
            "status": "queued",
            "stage": "等待执行",
            "message": "已加入流水线",
            "attempt": 0,
            "max_attempts": 1 + retry_limit,
            "failure_code": "",
            "retryable": False,
            "next_retry_at": None,
            "stop_requested": False,
            "created_at": created_at,
            "started_at": None,
            "finished_at": None,
            "log_path": None,
            "log_paths": [],
            "credential_path": None,
            "phone_verified": False,
        }
        return job_id

    def _ensure_workers(self, count: int) -> None:
        from .codex_worker import WorkerSettings, worker_main

        with self._lock:
            self._workers = [worker for worker in self._workers if worker.is_alive()]
            if self._task_queue is None:
                self._task_queue = queue.Queue()
                self._result_queue = queue.Queue()
            while len(self._workers) < count:
                worker = threading.Thread(
                    target=worker_main,
                    args=(
                        WorkerSettings(
                            project_root=Path(self.settings.project_root),
                            data_dir=self._data_dir,
                        ),
                        self._task_queue,
                        self._result_queue,
                    ),
                    name=f"codex-worker-{len(self._workers) + 1}",
                    daemon=True,
                )
                worker.start()
                self._workers.append(worker)

    def _dispatch_locked(self, job: dict[str, Any], mailbox: dict[str, Any]) -> str:
        job["attempt"] = int(job.get("attempt") or 0) + 1
        attempt = int(job["attempt"])
        log_path = self._log_dir / (
            f"codex-{job.get('account_id')}-{job['id'][:8]}-a{attempt}.log"
        )
        dispatch_id = uuid.uuid4().hex
        job.update(
            status="running",
            stage="登录与授权",
            message=f"正在执行第 {attempt}/{job['max_attempts']} 次",
            retryable=False,
            next_retry_at=None,
            started_at=job.get("started_at") or _now(),
            finished_at=None,
            log_path=str(log_path),
        )
        job.setdefault("log_paths", []).append(str(log_path))
        self.mailbox_store.update_codex(
            str(job.get("email") or ""),
            status="running",
            message=f"流水线执行中（第 {attempt}/{job['max_attempts']} 次）",
        )
        # Fresh cancel flag for this attempt; a retry gets a clean (unset) Event so
        # an earlier stop can't pre-cancel it. The worker runs in-process (thread),
        # so the Event object passes through the queue by reference, not pickled.
        cancel_event = threading.Event()
        self._cancel_events[job["id"]] = cancel_event
        self._task_queue.put(
            {
                "dispatch_id": dispatch_id,
                "job_id": job["id"],
                "attempt": attempt,
                "mailbox": mailbox,
                "log_path": str(log_path),
                "cancel_event": cancel_event,
            }
        )
        return dispatch_id

    @staticmethod
    def _failure_info(message: str, status: str = "", http_status: Any = None) -> tuple[str, bool, int]:
        text = f"{status} {message}".casefold()
        # gcash 提炼 failures are terminal for that account: retrying would log
        # in again and burn another extraction round for the same outcome.
        # Checked before the generic "超时" rule below, which would otherwise
        # mark a scan/extraction timeout as retryable.
        if "gcash_extract_failed" in text:
            return "gcash_extract_failed", False, 0
        # OpenAI 风控把提交邮箱的流程甩去了 accounts.google.com 之类的第三方登录页：
        # 救不回来，重试只会再烧一个取号。必须排在 register_failed / 超时 之前。
        if "openai_risk_block" in text:
            return "openai_risk_block", False, 0
        # 地址已经有 OpenAI 账号：注册不了（已存在）、也登录不进去（密码不是我们的），
        # 重试只会再烧一个取号。必须排在 register_failed / 超时 规则之前。
        if "account_already_registered" in text:
            return "account_already_registered", False, 0
        # A registration attempt consumes the rented mailbox: the activation is
        # cancelled on the way out, so the same account can never be retried.
        # Must stay ahead of the generic "超时" rule, which would otherwise mark
        # a 验证码等待超时 as retryable.
        if "register_failed" in text:
            return "register_failed", False, 0
        # Dead/removed account (OpenAI 身份验证错误 · account_deactivated) — the
        # email itself is unusable, retrying only burns SMS numbers. Mark it so
        # _handle_result_locked ends the job as "deactivated" instead of failed.
        if "account_deactivated" in text or "已被删除或停用" in text or "账户已被删除" in text:
            return "account_deactivated", False, 0
        if "等待通用 api 验证码超时" in text:
            return "mailbox_otp_timeout", True, 15
        if any(value in text for value in ("rate_limit", "too many", "请求过多")):
            return "rate_limited", True, 180
        # OpenAI transient server-error screens ("糟糕，出错了 / Operation timed
        # out") and the MV3 bridge going idle ("浏览器桥接超时") are both worth a
        # retry — the account is fine, the environment hiccuped.
        if "openai_transient" in text or "浏览器桥接超时" in text or "超时" in text:
            return "transient_network", True, 0
        if any(
            value in text
            for value in (
                "tls",
                "sslerror",
                "ssl connect",
                "timed out",
                "timeout",
                "connection reset",
                "connection aborted",
                "proxyerror",
                "temporary failure",
                "curl: (28)",
                "curl: (35)",
            )
        ):
            return "transient_network", True, 0
        try:
            code = int(http_status or 0)
        except (TypeError, ValueError):
            code = 0
        if code in {408, 425, 429, 500, 502, 503, 504}:
            return "transient_http", True, 180 if code == 429 else 0
        if "no_balance" in text or "余额" in text:
            return "sms_no_balance", False, 0
        if "bad_key" in text or "api key" in text:
            return "sms_bad_key", False, 0
        if "fraud_guard" in text or "suspicious behavior" in text:
            return "fraud_guard", False, 0
        if "phone_number_in_use" in text or "phone number already in use" in text:
            return "phone_number_in_use", False, 0
        if "邮箱" in text and any(value in text for value in ("凭证", "refresh", "未就绪")):
            return "mailbox_unavailable", False, 0
        return "task_failed", False, 0

    @staticmethod
    def _phone_from_log(path: str | None) -> str:
        if not path:
            return ""
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if "手机号验证通过" not in text:
            return ""
        matches = _PHONE_ATTEMPT.findall(text)
        return f"+{matches[-1]}" if matches else ""

    def _handle_result_locked(self, job: dict[str, Any], response: dict[str, Any], pipeline: dict[str, Any]) -> None:
        # The attempt has reported back; its cancel flag is spent either way.
        self._cancel_events.pop(str(job.get("id") or ""), None)
        result = response.get("result") if isinstance(response.get("result"), dict) else {}
        error = str(response.get("error") or "")
        error_type = str(response.get("error_type") or "")
        if error:
            status = "failed"
            message = f"{error_type}: {error}" if error_type else error
            credential_path = None
            http_status = None
        elif result.get("ok"):
            status = "success"
            message = str(result.get("message") or "Codex OAuth 完成")
            credential_path = str(result.get("file_path") or "") or None
            http_status = result.get("http_status")
        else:
            status = str(result.get("status") or "failed")
            message = str(result.get("message") or "Codex OAuth 失败")
            credential_path = None
            http_status = result.get("http_status")

        # Worker/vendor errors are untrusted text.  Sanitize once before any
        # scheduler or mailbox state is persisted so new state files never
        # retain credentials accidentally embedded in an exception message.
        message = _redact_log_text(message)[:500]

        if status == "success":
            phone_number = self._phone_from_log(job.get("log_path"))
            job.update(
                status="success",
                stage="已完成",
                message=message[:500],
                credential_path=credential_path,
                phone_verified=bool(phone_number),
                phone_number=phone_number,
                failure_code="",
                retryable=False,
                next_retry_at=None,
                finished_at=_now(),
            )
            self.mailbox_store.update_codex(
                str(job.get("email") or ""),
                status="success",
                message=message[:500],
                credential_path=credential_path,
                phone_verified=bool(phone_number),
                phone_number=phone_number or None,
            )
            return

        if status in {"deactivated", "skipped", "stopped"}:
            job.update(
                status=status,
                stage="已结束",
                message=message[:500],
                failure_code=status,
                retryable=False,
                next_retry_at=None,
                finished_at=_now(),
            )
            self.mailbox_store.update_codex(
                str(job.get("email") or ""), status=status, message=message[:500]
            )
            return

        failure_code, retryable, minimum_delay = self._failure_info(message, status, http_status)
        # A dead account (account_deactivated) is terminal — record it as
        # "deactivated" so the mailbox is flagged and the job is never retried.
        if failure_code == "account_deactivated":
            job.update(
                status="deactivated",
                stage="账号不可用",
                message=message[:500],
                failure_code=failure_code,
                retryable=False,
                next_retry_at=None,
                finished_at=_now(),
            )
            self.mailbox_store.update_codex(
                str(job.get("email") or ""), status="deactivated", message=message[:500]
            )
            return
        can_retry = (
            retryable
            and int(job.get("attempt") or 0) < int(job.get("max_attempts") or 1)
            and not bool(pipeline.get("stop_requested"))
            and not bool(job.get("stop_requested"))
        )
        if can_retry:
            base = int(pipeline.get("retry_backoff_seconds") or 30)
            exponent = max(0, int(job.get("attempt") or 1) - 1)
            delay = max(minimum_delay, min(600, base * (3**exponent)))
            job.update(
                status="retry_wait",
                stage="等待重试",
                message=f"临时失败，{delay} 秒后重试：{message[:360]}",
                failure_code=failure_code,
                retryable=True,
                next_retry_at=_after(delay),
                finished_at=None,
            )
            self.mailbox_store.update_codex(
                str(job.get("email") or ""),
                status="retry_wait",
                message=f"临时失败，等待第 {int(job.get('attempt') or 0)+1}/{job['max_attempts']} 次执行",
            )
            return

        job.update(
            status="failed",
            stage="执行失败",
            message=message[:500],
            failure_code=failure_code,
            retryable=retryable,
            next_retry_at=None,
            finished_at=_now(),
        )
        if failure_code == "openai_risk_block" and str(job.get("source") or "").lower() == "smsbower_gmail":
            # 这类 smsbower 注册号已经被 OpenAI 风控判死。job 必须保留在流水线
            # 历史里继续计入失败数，但账号素材本身直接删除，避免清单和
            # mailboxes.json 长期堆积永远不会再用的记录。
            account_id = str(job.get("account_id") or "")
            if account_id:
                self.mailbox_store.delete(account_id)
            return
        self.mailbox_store.update_codex(
            str(job.get("email") or ""), status="failed", message=message[:500]
        )

    def _supply_due(self, pipeline_id: str, inflight: dict[str, str]) -> bool:
        """True when it is time to rent the next mailbox.

        取一个号就立刻注册一个，注册完（成功或失败都算）才租下一个：号一旦
        租下来就开始计费，提前批量租号等于让后面的号干等着付租金。

        取号失败（多半是库存空的 "No mails yet"）**不结束流水线**，只是把下一次
        尝试推迟到 `supply_retry_at`；主循环照常以 0.5s 转，所以暂停/停止依然
        即时生效——**绝不要在这里 sleep**。
        """

        with self._lock:
            pipeline = self._pipelines.get(pipeline_id)
            if pipeline is None:
                return False
            if pipeline.get("stop_requested") or pipeline.get("pause_requested"):
                return False
            if int(pipeline.get("supply_remaining") or 0) <= 0 or inflight:
                return False
            retry_at = str(pipeline.get("supply_retry_at") or "")
            if retry_at and _parse_time(retry_at) > time.time():
                return False
            next_supply_at = str(pipeline.get("next_supply_at") or "")
            if next_supply_at and _parse_time(next_supply_at) > time.time():
                return False
            job_ids = [str(value) for value in pipeline.get("job_ids") or []]
            return all(
                self._jobs[job_id].get("status") in self._TERMINAL_JOBS
                for job_id in job_ids
                if job_id in self._jobs
            )

    def _supply_next(
        self,
        pipeline_id: str,
        mailboxes: dict[str, dict[str, Any]],
        supplier: Callable[[], str],
    ) -> None:
        """Rent one mailbox and append it to the running pipeline as a job."""

        from .notice_store import notices

        with self._lock:
            pipeline = self._pipelines.get(pipeline_id)
            if pipeline is None:
                return
            index = int(pipeline.get("supply_acquired") or 0) + 1
            total = int(pipeline.get("supply_total") or 0)
            retry_limit = int(pipeline.get("retry_limit") or 0)
            retrying = int(pipeline.get("supply_failures") or 0) > 0
        # 重试时不再刷这条：失败每隔几秒重来一次，会把通知栏冲干净。
        if not retrying:
            notices.push(f"正在取第 {index}/{total} 个 smsbower 邮箱……", scope="register")
        try:
            email = str(supplier() or "").strip()
            if not email:
                raise RuntimeError("取号接口没有返回邮箱地址")
            mailbox = self._prepare_mailbox(email, register_account=True)
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator as-is
            message = f"{exc}"[:300]
            with self._lock:
                pipeline = self._pipelines.get(pipeline_id)
                if pipeline is None:
                    return
                # 取不到号**绝不结束流水线**：最常见的失败是库存空
                # （"No mails yet"），过一会儿就有货了，而中途收工等于把这一批
                # 剩下的计划全丢掉、还要人重新点一次。只把下一次尝试推迟。
                delay = max(1, int(pipeline.get("supply_retry_seconds") or 10))
                failures = int(pipeline.get("supply_failures") or 0) + 1
                pipeline["supply_failures"] = failures
                pipeline["supply_error"] = message
                pipeline["supply_retry_at"] = _after(delay)
                pipeline["next_supply_at"] = None
                self._persist_locked()
            logging.getLogger(__name__).warning(
                "[smsbower-gmail] 取号失败（第 %d 次），%d 秒后重试：%s", failures, delay, message
            )
            # 每 10s 一条会把通知刷爆：第一次和之后每约一分钟各推一条就够了。
            if failures == 1 or delay * failures % 60 < delay:
                notices.push(
                    f"第 {index}/{total} 个取号失败，{delay} 秒后重试（已失败 {failures} 次）：{message}",
                    level="warn",
                    scope="register",
                )
            return
        with self._lock:
            pipeline = self._pipelines.get(pipeline_id)
            if pipeline is None:
                return
            job_id = self._new_job_locked(pipeline_id, mailbox, retry_limit, _now())
            mailboxes[job_id] = mailbox
            pipeline.setdefault("job_ids", []).append(job_id)
            pipeline["supply_remaining"] = max(0, int(pipeline.get("supply_remaining") or 0) - 1)
            pipeline["supply_acquired"] = index
            # 取到号了就把上一轮的失败痕迹清掉，别让界面一直挂着旧错误。
            pipeline["supply_error"] = ""
            pipeline["supply_failures"] = 0
            pipeline["supply_retry_at"] = None
            pipeline["next_supply_at"] = None
            self._persist_locked()
        notices.push(f"第 {index}/{total} 个已取到 {email}，开始注册", scope="register")

    def _run_pipeline(
        self,
        pipeline_id: str,
        mailboxes: dict[str, dict[str, Any]],
        supplier: Callable[[], str] | None = None,
    ) -> None:
        inflight: dict[str, str] = {}
        with self._lock:
            pipeline = self._pipelines.get(pipeline_id)
            if pipeline is None:
                return
            pipeline.update(
                status="paused" if pipeline.get("pause_requested") else "running",
                started_at=pipeline.get("started_at") or _now(),
            )
            self._persist_locked()

        while True:
            # 调度线程死了就等于整条流水线停摆：job 永远停在 running、
            # inflight 永不清空 → 不再取号、不再收工，而且**没有任何报错**
            # 会浮到界面上。任何一轮出的意外都只跳过这一轮，绝不结束循环。
            try:
                # 取号是网络调用（几秒），刻意放在锁外面，别让接口卡住整个面板。
                if supplier is not None and self._supply_due(pipeline_id, inflight):
                    self._supply_next(pipeline_id, mailboxes, supplier)
                    continue
                with self._lock:
                    pipeline = self._pipelines.get(pipeline_id)
                    if pipeline is None:
                        return
                    job_ids = [str(value) for value in pipeline.get("job_ids") or []]
                    changed = False
                    if pipeline.get("stop_requested"):
                        for job_id in job_ids:
                            job = self._jobs.get(job_id)
                            if job and job.get("status") in {"queued", "retry_wait"}:
                                job.update(
                                    status="stopped",
                                    stage="已停止",
                                    message="流水线已停止，任务未再派发",
                                    next_retry_at=None,
                                    finished_at=_now(),
                                )
                                self.mailbox_store.update_codex(
                                    str(job.get("email") or ""),
                                    status="stopped",
                                    message="流水线停止前尚未执行",
                                )
                                changed = True

                    now_ts = time.time()
                    ready = [] if pipeline.get("pause_requested") else [
                        self._jobs[job_id]
                        for job_id in job_ids
                        if job_id in self._jobs
                        and self._jobs[job_id].get("status") in {"queued", "retry_wait"}
                        and (
                            self._jobs[job_id].get("status") == "queued"
                            or _parse_time(self._jobs[job_id].get("next_retry_at")) <= now_ts
                        )
                    ]
                    ready.sort(key=lambda item: (str(item.get("next_retry_at") or ""), str(item.get("created_at") or "")))
                    slots = max(0, int(pipeline.get("concurrency") or 1) - len(inflight))
                    for job in ready[:slots]:
                        if pipeline.get("stop_requested") or pipeline.get("pause_requested"):
                            break
                        dispatch_id = self._dispatch_locked(job, mailboxes[job["id"]])
                        inflight[dispatch_id] = job["id"]
                        changed = True
                    jobs = [self._jobs[job_id] for job_id in job_ids if job_id in self._jobs]
                    all_terminal = all(job.get("status") in self._TERMINAL_JOBS for job in jobs)
                    if supplier is None:
                        all_terminal = bool(jobs) and all_terminal
                    # 还欠着号没租（包括暂停期间）就不能收工，否则"取号+注册 N 个"
                    # 会在第一个账号跑完时就宣告完成。停止请求下不再补号。
                    supply_pending = (
                        supplier is not None
                        and int(pipeline.get("supply_remaining") or 0) > 0
                        and not pipeline.get("stop_requested")
                    )
                    if changed:
                        self._persist_locked()
                    if all_terminal and not inflight and not supply_pending:
                        # A stopped batch may still contain truthful success/failure
                        # results from work that was already in flight.  Keep those
                        # per-job results, while making the batch-level state reflect
                        # the user's stop request.
                        pipeline["status"] = "stopped" if pipeline.get("stop_requested") else "completed"
                        pipeline["finished_at"] = _now()
                        self._persist_locked()
                        return

                try:
                    response = self._result_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if not isinstance(response, dict):
                    continue
                dispatch_id = str(response.get("dispatch_id") or "")
                job_id = inflight.pop(dispatch_id, None)
                if job_id is None:
                    continue
                with self._lock:
                    pipeline = self._pipelines.get(pipeline_id)
                    job = self._jobs.get(job_id)
                    if pipeline is None or job is None:
                        continue
                    self._handle_result_locked(job, response, pipeline)
                    if (
                        supplier is not None
                        and int(pipeline.get("supply_remaining") or 0) > 0
                        and not pipeline.get("stop_requested")
                    ):
                        interval = max(0, int(pipeline.get("next_account_interval_seconds") or 0))
                        pipeline["next_supply_at"] = _after(interval) if interval else None
                    self._persist_locked()
            except Exception:  # noqa: BLE001 - one bad tick must not kill the pipeline
                logging.getLogger(__name__).exception(
                    "流水线调度循环本轮异常，已跳过并继续：pipeline=%s", pipeline_id
                )
                time.sleep(0.5)

    def pause_pipeline(self, pipeline_id: str) -> bool:
        """Pause future dispatches while allowing already-running jobs to finish."""

        with self._lock:
            pipeline = self._pipelines.get(str(pipeline_id or ""))
            if not pipeline or str(pipeline.get("status") or "") not in {"queued", "running"}:
                return False
            pipeline.update(
                pause_requested=True,
                status="paused",
                paused_at=_now(),
            )
            self._persist_locked()
            return True

    def resume_pipeline(self, pipeline_id: str) -> bool:
        """Resume dispatching queued and retry-wait jobs in a paused pipeline."""

        with self._lock:
            pipeline = self._pipelines.get(str(pipeline_id or ""))
            if (
                not pipeline
                or str(pipeline.get("status") or "") != "paused"
                or pipeline.get("stop_requested")
            ):
                return False
            pipeline.update(
                pause_requested=False,
                status="running",
                paused_at=None,
                resumed_at=_now(),
            )
            self._persist_locked()
            return True

    def stop_pipeline(self, pipeline_id: str) -> bool:
        with self._lock:
            pipeline = self._pipelines.get(str(pipeline_id or ""))
            if not pipeline or str(pipeline.get("status") or "") not in self._ACTIVE_PIPELINES:
                return False
            pipeline["pause_requested"] = False
            pipeline["stop_requested"] = True
            pipeline["status"] = "stopping"
            for job_id in pipeline.get("job_ids") or []:
                job = self._jobs.get(str(job_id))
                if job and job.get("status") == "running":
                    job["stop_requested"] = True
                    job["message"] = "已停止派发后续任务；当前网络步骤将执行完"
                    event = self._cancel_events.get(str(job_id))
                    if event is not None:
                        event.set()
            self._persist_locked()
            return True

    def stop(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(str(job_id or ""))
            if not job or job.get("status") not in self._ACTIVE_JOBS:
                return False
            if job.get("status") in {"queued", "retry_wait"}:
                job.update(
                    status="stopped",
                    stage="已停止",
                    message="任务在执行前被停止",
                    next_retry_at=None,
                    finished_at=_now(),
                )
            else:
                job["stop_requested"] = True
                job["message"] = "已请求停止重试；当前网络步骤将执行完"
                event = self._cancel_events.get(str(job_id or ""))
                if event is not None:
                    event.set()
            self._persist_locked()
            return True

    def is_account_active(self, email: str) -> bool:
        target = str(email or "").strip().casefold()
        with self._lock:
            return any(
                str(job.get("email") or "").casefold() == target
                and str(job.get("status") or "") in self._ACTIVE_JOBS
                for job in self._jobs.values()
            )


__all__ = ["CodexJobManager"]
