"""Locked and atomic persistence for YanPort state."""

from __future__ import annotations

import copy
import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

REGISTRY_VERSION = 1


def empty_registry() -> dict[str, Any]:
    return {
        "version": REGISTRY_VERSION,
        "generation": 0,
        "contexts": {},
        "reservations": {},
    }


class StateStore:
    def __init__(self, root: Path | str | None = None) -> None:
        if root is None:
            explicit = os.environ.get("YAN_PORT_STATE_HOME")
            xdg_state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
            root = Path(explicit) if explicit else xdg_state / "yan-port"
        self.root = Path(root)
        self.registry_path = self.root / "registry.json"
        self.lock_path = self.root / "registry.lock"
        self.journal_path = self.root / "route-transaction.json"
        self.leases_path = self.root / "leases"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.leases_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.leases_path.chmod(0o700)

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.ensure()
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with os.fdopen(descriptor, "r+") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                yield
                fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            # fdopen owns the descriptor after successful construction.
            pass

    def load(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return empty_registry()
        payload = json.loads(self.registry_path.read_text())
        if payload.get("version") != REGISTRY_VERSION:
            raise RuntimeError(
                f"Unsupported YanPort registry version {payload.get('version')!r}; "
                f"expected {REGISTRY_VERSION}."
            )
        return payload

    def write(self, payload: dict[str, Any], *, path: Path | None = None) -> None:
        self.ensure()
        destination = path or self.registry_path
        temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(destination)
            destination.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)

    def clone(self, payload: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(payload)

    def lease_path(self, owner_id: str) -> Path:
        return self.leases_path / f"{owner_id}.json"

    def remove_journal(self) -> None:
        self.journal_path.unlink(missing_ok=True)
