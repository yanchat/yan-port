"""Stable Git checkout and worktree identity detection."""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import ContextError

_CODEX_WORKTREE = re.compile(r"(?:^|/)\.codex/worktrees/([^/]+)/")


@dataclass(frozen=True, slots=True)
class ContextInfo:
    checkout_path: str
    primary_path: str
    git_common_dir: str
    kind: str
    context_id: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _git(cwd: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "not a Git checkout"
        raise ContextError(f"Cannot identify YanPort context at {cwd}: {detail}")
    return result.stdout.strip()


def _primary_worktree(cwd: Path) -> Path:
    output = _git(cwd, "worktree", "list", "--porcelain")
    for line in output.splitlines():
        if line.startswith("worktree "):
            return Path(line.removeprefix("worktree ")).resolve()
    raise ContextError(f"Git returned no primary worktree for {cwd}")


def detect_context(cwd: Path | str | None = None) -> ContextInfo:
    requested = Path(cwd or Path.cwd()).resolve()
    checkout = Path(_git(requested, "rev-parse", "--show-toplevel")).resolve()
    primary = _primary_worktree(checkout)
    common_raw = _git(checkout, "rev-parse", "--path-format=absolute", "--git-common-dir")
    common_dir = Path(common_raw).resolve()
    if checkout == primary:
        kind = "local"
        context_id = "main"
    else:
        kind = "worktree"
        match = _CODEX_WORKTREE.search(f"{checkout.as_posix()}/")
        if match:
            context_id = f"wt-{match.group(1).lower()}"
        else:
            digest = hashlib.sha256(str(checkout).encode()).hexdigest()[:8]
            context_id = f"wt-{digest}"
    return ContextInfo(
        checkout_path=str(checkout),
        primary_path=str(primary),
        git_common_dir=str(common_dir),
        kind=kind,
        context_id=context_id,
    )
