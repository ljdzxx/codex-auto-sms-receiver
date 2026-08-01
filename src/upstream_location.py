from __future__ import annotations

from pathlib import Path


UPSTREAM_NAME = "turb-gpt-free-register"


def upstream_candidates(project_root: Path) -> tuple[Path, Path]:
    """Return the standalone vendor path and its former sibling location."""

    root = Path(project_root)
    return (
        root / "vendor" / UPSTREAM_NAME,
        root.parent / UPSTREAM_NAME,
    )


def resolve_upstream_root(project_root: Path) -> Path:
    """Return the OAuth runtime bundled inside this standalone project."""

    return upstream_candidates(project_root)[0]


__all__ = ["UPSTREAM_NAME", "resolve_upstream_root", "upstream_candidates"]
