from __future__ import annotations

import json
import multiprocessing
import queue
import threading
import time
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.codex_service import CodexJobManager
from src.codex_worker import worker_main
from src.mailbox_store import MailboxStore


def _settings(tmp_path: Path):
    return SimpleNamespace(
        project_root=Path(__file__).resolve().parents[1],
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )


def _wait_for(predicate, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition did not become true")


def _mailboxes(tmp_path: Path, count: int = 3):
    store = MailboxStore(tmp_path / "data")
    lines = [f"user{index}@example.com----https://mail.test/{index}" for index in range(count)]
    store.import_text("generic_api", "\n".join(lines))
    return store, [f"user{index}@example.com" for index in range(count)]


def _install_fake_workers(manager, *, handler, worker_count: int):
    task_queue: queue.Queue = queue.Queue()
    result_queue: queue.Queue = queue.Queue()
    threads: list[threading.Thread] = []

    def worker():
        while True:
            task = task_queue.get()
            if task is None:
                return
            result_queue.put(handler(task))

    for index in range(worker_count):
        thread = threading.Thread(target=worker, name=f"test-worker-{index}", daemon=True)
        thread.start()
        threads.append(thread)

    def ensure_workers(_count):
        manager._task_queue = task_queue
        manager._result_queue = result_queue

    manager._ensure_workers = ensure_workers
    return task_queue, threads


def test_pipeline_honors_concurrency_and_retries_only_transient_failures(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    attempts = defaultdict(int)
    active = 0
    maximum_active = 0
    state_lock = threading.Lock()

    def handler(task):
        nonlocal active, maximum_active
        email = task["mailbox"]["email"]
        attempts[email] += 1
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            time.sleep(0.04)
            Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
            Path(task["log_path"]).write_text(
                "2026-07-29 01:00:00,000 [INFO] [Codex] 手机验证尝试 1/2，provider=hero, activation_id=x, 号码=+84123456789\n"
                "2026-07-29 01:00:01,000 [INFO] [Codex] 手机号验证通过\n",
                encoding="utf-8",
            )
            if email == emails[0] and attempts[email] == 1:
                return {
                    "dispatch_id": task["dispatch_id"],
                    "job_id": task["job_id"],
                    "attempt": task["attempt"],
                    "error_type": "SSLError",
                    "error": "TLS connect error curl: (35)",
                }
            return {
                "dispatch_id": task["dispatch_id"],
                "job_id": task["job_id"],
                "attempt": task["attempt"],
                "result": {
                    "ok": True,
                    "status": "success",
                    "message": "done",
                    "file_path": str(tmp_path / f"{email}.json"),
                },
            }
        finally:
            with state_lock:
                active -= 1

    _install_fake_workers(manager, handler=handler, worker_count=2)
    pipeline = manager.start_batch(
        emails,
        concurrency=2,
        retry_limit=1,
        retry_backoff_seconds=5,
    )

    def completed_pipeline():
        value = manager.pipeline_overview(pipeline["id"])
        return value if not value["active"] else None

    finished = _wait_for(completed_pipeline, timeout=8)

    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 3
    assert maximum_active == 1
    assert attempts[emails[0]] == 2
    jobs = {row["email"]: row for row in manager.list_jobs()}
    assert jobs[emails[0]]["attempt"] == 2
    assert jobs[emails[0]]["phone_number"] == "+84123456789"
    assert jobs[emails[0]]["has_credential"] is True
    state_text = (tmp_path / "data" / "pipeline-state.json").read_text(encoding="utf-8")
    assert "https://mail.test" not in state_text


def test_pipeline_stop_cancels_queued_but_preserves_running_result(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path, count=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    started = threading.Event()
    release = threading.Event()

    def handler(task):
        started.set()
        assert release.wait(timeout=3)
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("completed", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {
                "ok": True,
                "status": "success",
                "message": "done",
                "file_path": str(tmp_path / "credential.json"),
            },
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1, retry_limit=2)
    assert started.wait(timeout=3)
    assert manager.pause_pipeline(pipeline["id"]) is True
    assert manager.pipeline_overview(pipeline["id"])["status"] == "paused"
    assert manager.stop_pipeline(pipeline["id"]) is True
    release.set()

    def completed_pipeline():
        value = manager.pipeline_overview(pipeline["id"])
        return value if not value["active"] else None

    finished = _wait_for(completed_pipeline)
    assert finished["status"] == "stopped"
    assert finished["counts"]["success"] == 1
    assert finished["counts"]["stopped"] == 1
    assert {row["status"] for row in manager.list_jobs()} == {"success", "stopped"}


def test_pipeline_pause_finishes_inflight_and_resume_dispatches_queue(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path, count=3)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    first_started = threading.Event()
    release_first = threading.Event()
    dispatched: list[str] = []
    dispatch_lock = threading.Lock()

    def handler(task):
        email = task["mailbox"]["email"]
        with dispatch_lock:
            dispatched.append(email)
            position = len(dispatched)
        if position == 1:
            first_started.set()
            assert release_first.wait(timeout=3)
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {
                "ok": True,
                "status": "success",
                "message": "done",
                "file_path": str(tmp_path / f"{email}.json"),
            },
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1)
    assert first_started.wait(timeout=3)

    assert manager.pause_pipeline(pipeline["id"]) is True
    paused = manager.pipeline_overview(pipeline["id"])
    assert paused["status"] == "paused"
    assert paused["active"] is True
    assert paused["counts"]["running"] == 1
    assert paused["counts"]["queued"] == 2
    assert manager.pause_pipeline(pipeline["id"]) is False

    release_first.set()
    _wait_for(lambda: manager.pipeline_overview(pipeline["id"])["counts"]["success"] == 1)
    time.sleep(0.15)
    assert dispatched == [emails[0]]
    persisted = json.loads((tmp_path / "data" / "pipeline-state.json").read_text(encoding="utf-8"))
    assert persisted["pipelines"][pipeline["id"]]["status"] == "paused"

    assert manager.resume_pipeline(pipeline["id"]) is True
    finished = _wait_for(
        lambda: (
            value
            if not (value := manager.pipeline_overview(pipeline["id"]))["active"]
            else None
        )
    )
    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 3
    assert dispatched == emails
    assert manager.resume_pipeline(pipeline["id"]) is False


def test_pipeline_forces_serial_execution_and_rejects_second_active_batch(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    with pytest.raises(ValueError, match="失败重试"):
        manager.start_batch(emails, retry_limit=100)

    blocker = threading.Event()

    def handler(task):
        blocker.wait(timeout=3)
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": False, "status": "failed", "message": "permanent"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=4)
    assert pipeline["concurrency"] == 1
    _wait_for(lambda: manager.pipeline_overview(pipeline["id"])["counts"].get("running"))
    with pytest.raises(RuntimeError, match="已有流水线"):
        manager.start_batch(emails)
    blocker.set()


def test_login_only_mode_flags_single_mailbox_and_rejects_multiple(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path, count=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    dispatched: list[dict] = []

    def handler(task):
        dispatched.append(task["mailbox"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("logged in", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "已登录 ChatGPT"},
        }

    with pytest.raises(ValueError, match="仅登录"):
        manager.start_batch(emails, concurrency=1, mode="login")

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails[:1], concurrency=1, mode="login")
    # 前端靠 pipeline.mode 判断"仅登录"，从而跳过任务完成后的浏览器清理
    assert pipeline["mode"] == "login"

    def completed_pipeline():
        value = manager.pipeline_overview(pipeline["id"])
        return value if not value["active"] else None

    finished = _wait_for(completed_pipeline)
    assert finished["counts"]["success"] == 1
    assert len(dispatched) == 1
    assert dispatched[0]["login_only"] is True
    assert "export_session" not in dispatched[0]
    # 仅登录不产出凭证文件
    assert manager.list_jobs()[0]["has_credential"] is False


def test_register_mode_runs_multiple_smsbower_gmail_accounts_serially(tmp_path: Path):
    mailbox_store = MailboxStore(tmp_path / "data")
    mailbox_store.import_text("generic_api", "old@example.com----https://mail.test/0")
    mailbox_store.import_activations(
        [{"email": "a@gmail.com", "mail_id": 4}, {"email": "b@gmail.com", "mail_id": 5}]
    )
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    # Only smsbower-gmail rentals can be registered.
    with pytest.raises(ValueError, match="smsbower-gmail"):
        manager.start_batch(["old@example.com"], concurrency=1, mode="register")

    dispatched: list[dict] = []

    def handler(task):
        dispatched.append(task["mailbox"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("registered", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "账号已注册并登录（尚未开启 2FA）"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    # 注册是批量操作：一次租一批号就是为了批量建号，两个账号都应能一起提交，
    # 但共享同一个浏览器，实际派发仍然是串行的（concurrency 强制钳到 1）。
    pipeline = manager.start_batch(["a@gmail.com", "b@gmail.com"], concurrency=1, mode="register")
    # 前端靠 pipeline.mode == 'register' 跳过任务完成后的浏览器清理（同仅登录/gcash）。
    assert pipeline["mode"] == "register"

    def completed_pipeline():
        value = manager.pipeline_overview(pipeline["id"])
        return value if not value["active"] else None

    finished = _wait_for(completed_pipeline)
    assert finished["counts"]["success"] == 2
    assert len(dispatched) == 2
    assert {task["mail_id"] for task in dispatched} == {4, 5}
    for task in dispatched:
        assert task["register_account"] is True
        # 取号账号没有任何登录素材，_otp_ready 不能拦下它。
        assert "export_session" not in task and "login_only" not in task


def test_register_failures_are_never_classified_as_retryable(tmp_path: Path):
    """注册失败一律不可重试：租用号在收尾时已 setStatus=2 退回。

    重试同一个账号必然在取码那步撞 ActivationGone——白跑一轮。所以 `_run_account_signup`
    把逃出去的异常统一打上 register_failed 令牌，这里锁住分类结果。
    """

    from src.codex_service import CodexJobManager as M

    for message in (
        "[Codex] register_failed：等待验证码超时（第 2 轮，120s 内没有收到新的验证码）",
        "[Codex] register_failed：2 个登录入口都没能进入邮箱表单（最后一次：标签页加载超时）",
    ):
        code, retryable, _delay = M._failure_info(message)
        assert (code, retryable) == ("register_failed", False), message
    # 更精确的终局分类保持原样（它们本来就不可重试）。
    assert M._failure_info("[Codex] openai_risk_block：被甩到第三方登录页")[:2] == (
        "openai_risk_block",
        False,
    )
    assert M._failure_info("[Codex] account_already_registered：已注册帐号")[:2] == (
        "account_already_registered",
        False,
    )


def test_acquire_register_rents_one_mailbox_at_a_time(tmp_path: Path):
    """取一个号 → 注册它 → 收尾后才取下一个，而不是一把租满再排队。"""

    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    timeline: list[str] = []
    rented = 0

    def supplier():
        nonlocal rented
        rented += 1
        email = f"rent{rented}@gmail.com"
        # 一个账号还在跑的时候绝不能来取号，否则新号一租下来就开始白付租金。
        assert not [item for item in timeline if item.endswith("-start") and f"{item[:-6]}-end" not in timeline]
        mailbox_store.import_activations([{"email": email, "mail_id": rented}])
        timeline.append(f"acquire:{email}")
        return email

    def handler(task):
        email = task["mailbox"]["email"]
        timeline.append(f"{email}-start")
        time.sleep(0.02)
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("registered", encoding="utf-8")
        timeline.append(f"{email}-end")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "账号已注册"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(
        [],
        concurrency=1,
        mode="register",
        supplier=supplier,
        supply_count=3,
        next_account_interval_seconds=0,
    )
    # 还没租到的号也要算进总数，否则进度会显示成 1/1 再跳成 1/2。
    assert pipeline["total"] == 3 and pipeline["supply_remaining"] == 3

    def completed_pipeline():
        value = manager.pipeline_overview(pipeline["id"])
        return value if not value["active"] else None

    finished = _wait_for(completed_pipeline, timeout=10)

    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 3 and finished["total"] == 3
    assert finished["supply_acquired"] == 3 and finished["supply_remaining"] == 0
    assert timeline == [
        "acquire:rent1@gmail.com",
        "rent1@gmail.com-start",
        "rent1@gmail.com-end",
        "acquire:rent2@gmail.com",
        "rent2@gmail.com-start",
        "rent2@gmail.com-end",
        "acquire:rent3@gmail.com",
        "rent3@gmail.com-start",
        "rent3@gmail.com-end",
    ]
    assert {row["email"] for row in mailbox_store.list_accounts()} == {
        "rent1@gmail.com",
        "rent2@gmail.com",
        "rent3@gmail.com",
    }


def test_next_account_interval_applies_only_after_a_job_finishes(tmp_path: Path):
    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    acquired_at: list[float] = []

    def supplier():
        acquired_at.append(time.monotonic())
        email = f"paced{len(acquired_at)}@gmail.com"
        mailbox_store.import_activations([{"email": email, "mail_id": len(acquired_at)}])
        return email

    def handler(task):
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("registered", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "账号已注册"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    started_at = time.monotonic()
    pipeline = manager.start_batch(
        [],
        concurrency=1,
        mode="register",
        supplier=supplier,
        supply_count=2,
        next_account_interval_seconds=1,
    )
    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=10,
    )

    assert finished["counts"]["success"] == 2
    assert acquired_at[0] - started_at < 0.8  # 首个账号立即取号。
    assert acquired_at[1] - acquired_at[0] >= 0.8  # 账号终态后才走处理下一个间隔。


def test_supply_failure_switches_to_retry_interval_instead_of_next_account_interval(tmp_path: Path):
    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    pipeline_id = "supply-reason-pipeline"
    with manager._lock:
        manager._pipelines[pipeline_id] = {
            "id": pipeline_id,
            "supply_total": 2,
            "supply_remaining": 1,
            "supply_acquired": 1,
            "supply_retry_seconds": 7,
            "supply_failures": 0,
            "supply_retry_at": None,
            "next_account_interval_seconds": 60,
            "next_supply_at": "2999-01-01T00:00:00+00:00",
            "retry_limit": 0,
            "job_ids": [],
        }

    manager._supply_next(
        pipeline_id,
        {},
        lambda: (_ for _ in ()).throw(RuntimeError("smsbower 邮箱接口：No mails yet")),
    )
    public = manager.pipeline_overview(pipeline_id)

    assert public["supply_failures"] == 1
    assert public["supply_retry_at"]
    assert not public.get("next_supply_at")


def test_supply_failure_retries_instead_of_ending_the_batch(tmp_path: Path):
    """取号失败（多半是库存空的 No mails yet）只推迟重试，绝不中断整批注册。

    号是一个一个租的，中途收工等于把这一批剩下的计划全丢掉、还要人重新点一次。
    """

    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    calls = 0

    def supplier():
        nonlocal calls
        calls += 1
        if calls in {1, 3}:  # 每个号都先撞一次库存空
            raise RuntimeError("smsbower 邮箱接口：No mails yet")
        email = f"acct{calls}@gmail.com"
        mailbox_store.import_activations([{"email": email, "mail_id": calls}])
        return email

    def handler(task):
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("registered", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "账号已注册"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(
        [],
        concurrency=1,
        mode="register",
        supplier=supplier,
        supply_count=2,
        supply_retry_seconds=1,
        next_account_interval_seconds=0,
    )

    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=20,
    )
    # 两次库存空都自己扛过去了，计划的 2 个号一个不少。
    assert calls == 4
    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 2
    # 取到号之后失败痕迹要清掉，别让界面一直挂着旧错误。
    assert not finished["supply_error"]


def test_supply_failure_keeps_the_pipeline_alive_until_stopped(tmp_path: Path):
    """一直取不到号就一直重试；只有用户点停止才收尾，已注册好的账号保留。"""

    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    calls = 0

    def supplier():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("smsbower 邮箱接口：No mails yet")
        mailbox_store.import_activations([{"email": "a@gmail.com", "mail_id": 7}])
        return "a@gmail.com"

    def handler(task):
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("registered", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "账号已注册"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(
        [],
        concurrency=1,
        mode="register",
        supplier=supplier,
        supply_count=3,
        supply_retry_seconds=1,
        next_account_interval_seconds=0,
    )

    live = _wait_for(
        lambda: (lambda value: value if int(value.get("supply_failures") or 0) >= 2 else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=15,
    )
    # 关键：还在重试，没有把整批判死。
    assert live["active"] is True
    assert "No mails yet" in live["supply_error"]
    assert live["supply_retry_at"]
    assert live["counts"]["success"] == 1

    assert manager.stop_pipeline(pipeline["id"]) is True
    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=10,
    )
    assert finished["status"] == "stopped"
    # 已经注册好的账号一个都不能丢。
    assert finished["counts"]["success"] == 1


def test_acquire_register_rejects_bad_supply_requests(tmp_path: Path):
    mailbox_store = MailboxStore(tmp_path / "data")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    # 边取号边处理只有注册模式支持：其它模式的账号必须先导入才有素材。
    with pytest.raises(ValueError, match="注册模式"):
        manager.start_batch([], concurrency=1, mode="oauth", supplier=lambda: "x@gmail.com", supply_count=1)
    with pytest.raises(ValueError, match="取号数量"):
        manager.start_batch([], concurrency=1, mode="register", supplier=lambda: "x@gmail.com", supply_count=0)
    pipeline = manager.start_batch(
        [], concurrency=1, mode="register", supplier=lambda: "x@gmail.com", supply_count=1000
    )
    assert pipeline["supply_total"] == 1000
    assert manager.stop_pipeline(pipeline["id"])
    # 没有 supplier 时空清单依然是错误，别把两条路径混在一起。
    with pytest.raises(ValueError, match="至少"):
        manager.start_batch([], concurrency=1, mode="register")


def test_generic_mailbox_timeouts_and_proxy_errors_are_retryable(tmp_path: Path):
    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)

    assert manager._failure_info(
        "GenericApiMailError: 等待通用 API 验证码超时；HTTP 200 但未提取到验证码"
    ) == ("mailbox_otp_timeout", True, 15)
    assert manager._failure_info(
        "GenericApiMailError: 网络请求失败（ProxyError）"
    ) == ("transient_network", True, 0)


def test_openai_risk_block_is_terminal_and_beats_the_retry_rules(tmp_path: Path):
    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)

    # 被甩到 accounts.google.com 是风控拦截，救不回来，重试只会再烧一个取号。
    assert manager._failure_info(
        "[Codex] openai_risk_block：提交邮箱后被 OpenAI 甩到第三方登录页"
        "（https://accounts.google.com/v3/signin/identifier），这是风控拦截、救不回来，放弃该账号"
    ) == ("openai_risk_block", False, 0)
    # 跨域跳转会销毁注入帧，报文里常常带"超时"字样——绝不能被判成可重试。
    assert manager._failure_info(
        "[Codex] openai_risk_block：提交邮箱后被甩到第三方登录页，页面动作超时"
    ) == ("openai_risk_block", False, 0)


def test_openai_risk_block_deletes_smsbower_account_but_keeps_failed_job(tmp_path: Path):
    mailbox_store = MailboxStore(tmp_path / "data")
    mailbox_store.import_activations([{"email": "blocked@gmail.com", "mail_id": 123}])
    account = mailbox_store.list_accounts()[0]
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    pipeline_id = "risk-pipeline"
    job_id = "risk-job"
    pipeline = {"id": pipeline_id, "retry_backoff_seconds": 30, "stop_requested": False}
    job = {
        "id": job_id,
        "pipeline_id": pipeline_id,
        "account_id": account["id"],
        "email": account["email"],
        "source": "smsbower_gmail",
        "attempt": 1,
        "max_attempts": 1,
    }

    manager._handle_result_locked(
        job,
        {
            "error": "[Codex] openai_risk_block：提交邮箱后被 OpenAI 甩到第三方登录页",
            "error_type": "RuntimeError",
        },
        pipeline,
    )

    assert job["status"] == "failed"
    assert job["failure_code"] == "openai_risk_block"
    assert mailbox_store.list_accounts() == []


def test_already_registered_address_is_terminal_not_retryable(tmp_path: Path):
    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)

    # 地址已有 OpenAI 账号：注册不了、也登录不进去，重试只会再烧一个取号。
    assert manager._failure_info(
        "[Codex] account_already_registered：已注册帐号 —— a@gmail.com 已存在 OpenAI 账号"
        "（提交邮箱后落到登录密码页），放弃该账号"
    ) == ("account_already_registered", False, 0)
    # 必须压过笼统的 register_failed 和"超时可重试"规则。
    assert manager._failure_info(
        "[Codex] account_already_registered：已注册帐号，等待验证码超时"
    ) == ("account_already_registered", False, 0)
    assert manager._failure_info(
        "[Codex] register_failed：等待验证码超时（第 2 轮）"
    ) == ("register_failed", False, 0)


def test_isolated_worker_process_starts_and_stops_cleanly(tmp_path: Path):
    context = multiprocessing.get_context("spawn")
    task_queue = context.Queue()
    result_queue = context.Queue()
    process = context.Process(
        target=worker_main,
        args=(_settings(tmp_path), task_queue, result_queue),
    )
    process.start()
    task_queue.put(None)
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    assert process.exitcode == 0


def test_pipeline_state_recovers_interrupted_jobs_after_restart(tmp_path: Path):
    mailbox_store, emails = _mailboxes(tmp_path, count=1)
    state = {
        "version": 1,
        "pipelines": {
            "pipeline-old": {
                "id": "pipeline-old",
                "status": "running",
                "concurrency": 1,
                "retry_limit": 1,
                "job_ids": ["job-old"],
                "created_at": "2026-07-29T00:00:00+00:00",
            }
        },
        "jobs": {
            "job-old": {
                "id": "job-old",
                "pipeline_id": "pipeline-old",
                "email": emails[0],
                "status": "running",
                "created_at": "2026-07-29T00:00:00+00:00",
                "log_paths": [],
            }
        },
    }
    path = tmp_path / "data" / "pipeline-state.json"
    path.write_text(json.dumps(state), encoding="utf-8")

    manager = CodexJobManager(_settings(tmp_path), mailbox_store)

    assert manager.pipeline_overview("pipeline-old")["status"] == "interrupted"
    job = manager.list_jobs()[0]
    assert job["status"] == "failed"
    assert job["failure_code"] == "service_restarted"
    assert mailbox_store.list_accounts()[0]["codex_status"] == "failed"


def test_public_job_ignores_deleted_or_outside_log_paths(tmp_path: Path):
    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    existing = log_dir / "codex-account-task.log"
    existing.write_text("safe log", encoding="utf-8")
    outside = tmp_path / "outside.log"
    outside.write_text("outside", encoding="utf-8")

    public = manager._public_job(
        {
            "id": "job-old",
            "message": "done",
            "log_path": str(log_dir / "deleted.log"),
            "log_paths": [str(existing), str(existing), str(outside)],
        }
    )

    assert public["has_log"] is True
    assert public["log_count"] == 1
    assert "log_path" not in public
    assert "log_paths" not in public

    existing.unlink()
    public = manager._public_job(
        {
            "id": "job-old",
            "message": "done",
            "log_path": str(existing),
            "log_paths": [str(outside)],
        }
    )
    assert public["has_log"] is False
    assert public["log_count"] == 0


def test_gcash_mode_requires_saved_tabs_and_forwards_them_to_the_worker(tmp_path: Path):
    from src.gcash_store import GcashTabStore

    mailbox_store, emails = _mailboxes(tmp_path, count=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    with pytest.raises(ValueError, match="绑定"):
        manager.start_batch(emails, concurrency=1, mode="gcash")

    GcashTabStore(tmp_path / "data").save(login_tab_id=101, extract_tab_id=202)
    dispatched: list[dict] = []

    def handler(task):
        dispatched.append(task["mailbox"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("gcash", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "gcash 提炼成功"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1, mode="gcash")
    # 前端靠 pipeline.mode 跳过收尾清理（会打断绑定的标签页）
    assert pipeline["mode"] == "gcash"

    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        )
    )
    assert finished["counts"]["success"] == 2
    assert len(dispatched) == 2
    for mailbox in dispatched:
        assert mailbox["gcash_extract"] is True
        assert (mailbox["gcash_login_tab_id"], mailbox["gcash_extract_tab_id"]) == (101, 202)
        assert "login_only" not in mailbox and "export_session" not in mailbox


def test_gcash_extraction_failure_is_never_retried(tmp_path: Path):
    from src.gcash_store import GcashTabStore

    mailbox_store, emails = _mailboxes(tmp_path, count=1)
    GcashTabStore(tmp_path / "data").save(login_tab_id=1, extract_tab_id=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}
    attempts: list[int] = []

    def handler(task):
        attempts.append(task["attempt"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("failed", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {
                "ok": False,
                "status": "failed",
                # 消息里带 "超时" —— 若没有 gcash_extract_failed 分类会被误判成可重试
                "message": "gcash_extract_failed：付款链接已打开但未等到扫码完成（超时）",
            },
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1, retry_limit=3, mode="gcash")

    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        )
    )
    assert finished["counts"]["failed"] == 1
    assert attempts == [1]
    assert manager.list_jobs()[0]["failure_code"] == "gcash_extract_failed"


def test_batch_assigns_pool_proxies_round_robin_per_account(tmp_path: Path):
    from src.proxy_store import ProxyStore

    mailbox_store, emails = _mailboxes(tmp_path, count=3)
    proxy_store = ProxyStore(tmp_path / "data")
    proxy_store.add_many("http://1.1.1.1:8001\nhttp://2.2.2.2:8002")
    proxy_store.set_enabled(True)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store, proxy_store=proxy_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    dispatched: list[dict] = []

    def handler(task):
        dispatched.append(task["mailbox"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("ok", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "done"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1)
    _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        )
    )

    # Three accounts over a two-proxy pool: 1 → 2 → 1 (cursor wraps, per account).
    assert [mailbox["proxy"]["host"] for mailbox in dispatched] == ["1.1.1.1", "2.2.2.2", "1.1.1.1"]
    assert all(mailbox["proxy"]["scheme"] == "http" for mailbox in dispatched)


def test_batch_omits_proxy_when_pool_is_disabled_or_empty(tmp_path: Path):
    from src.proxy_store import ProxyStore

    mailbox_store, emails = _mailboxes(tmp_path, count=1)
    proxy_store = ProxyStore(tmp_path / "data")
    proxy_store.add_many("http://1.1.1.1:8001")
    manager = CodexJobManager(_settings(tmp_path), mailbox_store, proxy_store=proxy_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    dispatched: list[dict] = []

    def handler(task):
        dispatched.append(task["mailbox"])
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("ok", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "done"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1)
    _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        )
    )
    # Pool switched off → no proxy key at all, so the worker clears the browser.
    assert "proxy" not in dispatched[0]


def test_state_persist_failure_never_kills_the_scheduler(tmp_path: Path, monkeypatch):
    """落盘失败只能丢状态，绝不能让整条流水线停摆。

    实测 2026-08-13：Windows 上 `os.replace` 撞到别的句柄（杀软扫描 / 同步盘）抛
    PermissionError，异常从 _persist_locked 冒到 _run_pipeline 的 while 循环（当时
    没有 try），调度线程当场死亡 —— job 永远停在 running、inflight 永不清空 →
    不再取号、不再收工，界面上还是"运行中"，现场只留下一个 .tmp 文件。
    """

    import os as _os

    mailbox_store, emails = _mailboxes(tmp_path, count=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    real_replace = _os.replace
    state_name = "pipeline-state.json"

    def flaky_replace(source, target, *args, **kwargs):
        if str(target).endswith(state_name):
            raise PermissionError(13, "another process has the file open")
        return real_replace(source, target, *args, **kwargs)

    monkeypatch.setattr("src.codex_service.os.replace", flaky_replace)
    monkeypatch.setattr("src.codex_service.time.sleep", lambda _seconds: None)

    def handler(task):
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("ok", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "done"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1)

    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=8,
    )
    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 2
    # 半成品不许留在 data/ 下：现场就是靠这个 .tmp 才定位到根因的。
    assert not list((tmp_path / "data").glob(".pipeline-state.json.*.tmp"))


def test_scheduler_loop_survives_an_unexpected_tick_error(tmp_path: Path):
    """调度循环任何一轮出意外都只能跳过这一轮，不能结束循环。

    线程一死，界面上流水线还是"运行中"，却再也不派发、不取号、不收工，而且没有
    任何报错浮出来——这是最难查的一类故障，所以循环体必须整体兜住。
    """

    mailbox_store, emails = _mailboxes(tmp_path, count=2)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    manager.availability = lambda: {"available": True, "reason": ""}

    real_dispatch = manager._dispatch_locked
    exploded: list[int] = []

    def flaky_dispatch(job, mailbox):
        # 派发前炸一次：job 还是 queued，下一轮应当照常重新派发。
        if not exploded:
            exploded.append(1)
            raise RuntimeError("simulated tick failure before dispatch")
        return real_dispatch(job, mailbox)

    manager._dispatch_locked = flaky_dispatch

    def handler(task):
        Path(task["log_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(task["log_path"]).write_text("ok", encoding="utf-8")
        return {
            "dispatch_id": task["dispatch_id"],
            "job_id": task["job_id"],
            "attempt": task["attempt"],
            "result": {"ok": True, "status": "success", "message": "done"},
        }

    _install_fake_workers(manager, handler=handler, worker_count=1)
    pipeline = manager.start_batch(emails, concurrency=1)

    finished = _wait_for(
        lambda: (lambda value: value if not value["active"] else None)(
            manager.pipeline_overview(pipeline["id"])
        ),
        timeout=8,
    )
    assert exploded == [1]
    assert finished["status"] == "completed"
    assert finished["counts"]["success"] == 2


def _stuff_history(manager, *, count: int, active_job: bool = True):
    """Fill the manager with finished history plus (optionally) one live job."""

    for index in range(count):
        pipeline_id = f"old-pipeline-{index}"
        job_id = f"old-job-{index}"
        manager._jobs[job_id] = {
            "id": job_id,
            "pipeline_id": pipeline_id,
            "email": f"old{index}@example.com",
            "status": "success",
            "created_at": f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}+00:00",
        }
        manager._pipelines[pipeline_id] = {
            "id": pipeline_id,
            "status": "completed",
            "created_at": "2026-01-01T00:00:00+00:00",
            "job_ids": [job_id],
        }
    if active_job:
        manager._jobs["live-job"] = {
            "id": "live-job",
            "pipeline_id": "live-pipeline",
            "email": "live@example.com",
            "status": "running",
            "created_at": "2020-01-01T00:00:00+00:00",  # 最老的一条，但还在跑
        }
        manager._pipelines["live-pipeline"] = {
            "id": "live-pipeline",
            "status": "running",
            "created_at": "2020-01-01T00:00:00+00:00",
            "job_ids": ["live-job"],
        }


def test_history_is_archived_so_the_state_file_stays_small(tmp_path: Path):
    """主状态文件每次派发/每个结果都要全量重写，必须有上界。

    活跃的东西一条都不许动——哪怕它是最老的那条。
    """

    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    retained = manager._RETAINED_JOBS
    _stuff_history(manager, count=retained + 100)

    with manager._lock:
        assert manager._archive_old_state_locked() is True
        manager._persist_locked()

    assert len(manager._jobs) == retained
    # 还在跑的 job 和它的流水线必须留下，尽管它的 created_at 是最老的。
    assert "live-job" in manager._jobs
    assert "live-pipeline" in manager._pipelines
    # 留下的是最近的那些，被移出的是最旧的那些。
    assert "old-job-0" not in manager._jobs
    assert f"old-job-{retained + 99}" in manager._jobs
    # 空壳流水线跟着一起归档。
    assert "old-pipeline-0" not in manager._pipelines

    archives = list((tmp_path / "data" / "pipeline-archive").glob("*.json"))
    assert len(archives) == 1
    archived = json.loads(archives[0].read_text(encoding="utf-8"))
    assert "old-job-0" in archived["jobs"]
    assert "old-pipeline-0" in archived["pipelines"]
    assert "live-job" not in archived["jobs"]

    # 归档后的状态文件必须还能被重新加载。
    reloaded = CodexJobManager(_settings(tmp_path), mailbox_store)
    assert len(reloaded._jobs) == retained


def test_archive_write_failure_drops_nothing(tmp_path: Path):
    """归档没写成就一条都不许删——文件大只是难看，丢历史是真丢。"""

    mailbox_store, _ = _mailboxes(tmp_path, count=1)
    manager = CodexJobManager(_settings(tmp_path), mailbox_store)
    _stuff_history(manager, count=manager._RETAINED_JOBS + 50, active_job=False)
    total = len(manager._jobs)
    manager._append_archive = lambda pipelines, jobs: False

    with manager._lock:
        assert manager._archive_old_state_locked() is False
    assert len(manager._jobs) == total
