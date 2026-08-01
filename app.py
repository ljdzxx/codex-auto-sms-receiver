from __future__ import annotations

import argparse
import logging
import os
import sys
import threading

from src.settings import load_settings
from src.log_retention import maintain_log_retention
from src.webapp import create_app


def _configure_utf8_stdio(streams=None) -> None:
    """Keep redirected Windows stdout/stderr logs consistently UTF-8."""

    targets = streams if streams is not None else (sys.stdout, sys.stderr)
    for stream in targets:
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (OSError, ValueError):
            # Some embedded/captured streams expose reconfigure but reject it.
            continue


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    # API polling is expected application traffic, not a useful frontend event.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _start_log_retention_loop(log_dir) -> None:
    """Re-apply disk bounds while the local console remains running."""

    def maintain() -> None:
        wake = threading.Event()
        while not wake.wait(6 * 60 * 60):
            try:
                result = maintain_log_retention(log_dir)
                if result["deleted_files"]:
                    logging.getLogger(__name__).info(
                        "日志保留策略已清理 %s 个旧文件，释放 %s 字节",
                        result["deleted_files"],
                        result["deleted_bytes"],
                    )
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "日志保留策略执行失败（%s）", type(exc).__name__
                )

    threading.Thread(
        target=maintain,
        name="log-retention",
        daemon=True,
    ).start()


def main() -> None:
    _configure_utf8_stdio()
    parser = argparse.ArgumentParser(
        description="Codex Auto SMS Receiver — 基于 HeroSMS 的 Codex 自动接码与 OAuth 登录工具"
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    _configure_logging(args.debug)
    settings = load_settings(host=args.host, port=args.port)
    retention = maintain_log_retention(settings.log_dir)
    if retention["deleted_files"]:
        logging.getLogger(__name__).info(
            "日志保留策略已清理 %s 个旧文件，释放 %s 字节",
            retention["deleted_files"],
            retention["deleted_bytes"],
        )
    _start_log_retention_loop(settings.log_dir)
    app = create_app(settings)

    print(f"WEBUI_URL=http://{settings.host}:{settings.port}", flush=True)
    print(f"BROWSER_EXECUTABLE={settings.browser_executable or 'NOT_FOUND'}", flush=True)
    pid_path = settings.data_dir / "server.pid"
    pid_path.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    try:
        app.run(
            host=settings.host,
            port=settings.port,
            debug=False,
            threaded=True,
            use_reloader=False,
        )
    finally:
        try:
            if pid_path.read_text(encoding="utf-8").strip() == str(os.getpid()):
                pid_path.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    main()
