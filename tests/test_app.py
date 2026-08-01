from __future__ import annotations

import logging

import app


class _FakeStream:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.calls: list[dict[str, str]] = []

    def reconfigure(self, **kwargs) -> None:
        if self.fail:
            raise ValueError("captured stream")
        self.calls.append(kwargs)


def test_configure_utf8_stdio_reconfigures_supported_streams_and_tolerates_captures():
    output = _FakeStream()
    captured = _FakeStream(fail=True)

    app._configure_utf8_stdio((output, object(), captured))

    assert output.calls == [{"encoding": "utf-8", "errors": "backslashreplace"}]


def test_configure_logging_suppresses_werkzeug_access_noise(monkeypatch):
    configured: dict = {}
    werkzeug = logging.getLogger("werkzeug")
    previous_level = werkzeug.level
    werkzeug.setLevel(logging.NOTSET)
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(app.logging, "basicConfig", lambda **kwargs: configured.update(kwargs))
            app._configure_logging(debug=False)

        assert configured["level"] == logging.INFO
        assert werkzeug.level == logging.WARNING
    finally:
        werkzeug.setLevel(previous_level)
