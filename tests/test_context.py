from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from yan_port.context import detect_context
from yan_port.errors import ContextError


def git(cwd: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)


def test_detects_primary_and_detached_worktree(tmp_path: Path) -> None:
    primary = tmp_path / "project"
    primary.mkdir()
    git(primary, "init", "-b", "main")
    git(primary, "config", "user.name", "YanPort Test")
    git(primary, "config", "user.email", "test@example.invalid")
    (primary / "README.md").write_text("test\n")
    git(primary, "add", "README.md")
    git(primary, "commit", "-m", "initial")

    local = detect_context(primary)
    assert local.kind == "local"
    assert local.context_id == "main"
    assert local.primary_path == str(primary)

    worktree = tmp_path / ".codex" / "worktrees" / "ac88" / "project"
    worktree.parent.mkdir(parents=True)
    git(primary, "worktree", "add", "--detach", str(worktree), "HEAD")
    linked = detect_context(worktree)
    assert linked.kind == "worktree"
    assert linked.context_id == "wt-ac88"
    assert linked.primary_path == str(primary)


def test_non_git_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="Cannot identify YanPort context"):
        detect_context(tmp_path)
