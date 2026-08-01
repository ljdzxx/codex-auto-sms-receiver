from pathlib import Path

from src.upstream_location import resolve_upstream_root


def _codex_stub(root: Path) -> Path:
    target = root / "core" / "codex_oauth.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# runtime stub\n", encoding="utf-8")
    return root


def test_runtime_is_always_the_vendored_copy(tmp_path: Path):
    project = tmp_path / "codex-auto-sms-receiver"
    vendored = _codex_stub(project / "vendor" / "turb-gpt-free-register")
    _codex_stub(tmp_path / "turb-gpt-free-register")

    assert resolve_upstream_root(project) == vendored
