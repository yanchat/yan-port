from __future__ import annotations

import json
import multiprocessing
import socket
import subprocess
from pathlib import Path

import pytest

from yan_port.context import detect_context
from yan_port.errors import CaddyError, ConflictError, ContextError
from yan_port.registry import StateStore
from yan_port.service import YanPortService


class RecordingCaddy:
    admin_socket = "/tmp/yan-port-test-admin.sock"

    def __init__(self) -> None:
        self.configs: list[str] = []
        self.fail = False
        self.crash = False

    def apply(self, content: str) -> None:
        if self.crash:
            self.crash = False
            raise RuntimeError("simulated process interruption")
        if self.fail:
            raise CaddyError("candidate rejected")
        self.configs.append(content)

    def validate(self, content: str) -> None:
        if self.fail:
            raise CaddyError("candidate rejected")
        self.configs.append(f"validated:{content}")

    def render(self, registry: dict[str, object]) -> str:
        from yan_port.caddy import render_caddyfile

        return render_caddyfile(registry, admin_socket=self.admin_socket)


class NoopCaddy:
    admin_socket = "/tmp/yan-port-test-admin.sock"

    def apply(self, content: str) -> None:
        del content

    def validate(self, content: str) -> None:
        del content

    def render(self, registry: dict[str, object]) -> str:
        from yan_port.caddy import render_caddyfile

        return render_caddyfile(registry, admin_socket=self.admin_socket)


class FixedTrustInspector:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def status(
        self, registry: dict[str, object], *, hostname: str | None = None
    ) -> dict[str, object]:
        del registry, hostname
        return self.payload


def allocate_worker(state_root: str, checkout: str, name: str) -> int:
    manager = YanPortService(StateStore(state_root), NoopCaddy())  # type: ignore[arg-type]
    return int(manager.allocate_port(name, cwd=checkout, preferred=25173)["port"])


def git(cwd: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def checkouts(tmp_path: Path) -> tuple[Path, Path]:
    primary = tmp_path / "project"
    primary.mkdir()
    git(primary, "init", "-b", "main")
    git(primary, "config", "user.name", "YanPort Test")
    git(primary, "config", "user.email", "test@example.invalid")
    (primary / "README.md").write_text("test\n")
    git(primary, "add", "README.md")
    git(primary, "commit", "-m", "initial")
    worktree = tmp_path / ".codex" / "worktrees" / "b742" / "project"
    worktree.parent.mkdir(parents=True)
    git(primary, "worktree", "add", "--detach", str(worktree), "HEAD")
    return primary, worktree


@pytest.fixture
def service(tmp_path: Path) -> tuple[YanPortService, RecordingCaddy, StateStore]:
    store = StateStore(tmp_path / "state")
    caddy = RecordingCaddy()
    return YanPortService(store, caddy), caddy, store  # type: ignore[arg-type]


def test_context_port_route_and_reservation_lifecycle(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, worktree = checkouts
    manager, caddy, _ = service
    local = manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    linked = manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    assert local["context_id"] == "main"
    assert linked["context_id"] == "wt-b742"
    assert local["route_domain"] == "example.localhost"
    assert linked["route_domain"] == "example-wt-b742.localhost"

    local_port = manager.allocate_port("hub", cwd=primary, preferred=25173)
    worktree_port = manager.allocate_port("hub", cwd=worktree, preferred=25173)
    assert local_port["port"] == 25173
    assert worktree_port["port"] != 25173

    route = manager.apply_route(
        "hub",
        hostname="hub.example-wt-b742.localhost",
        upstream=f"http://127.0.0.1:{worktree_port['port']}",
        port_service="hub",
        cwd=worktree,
    )
    assert route["hostname"] == "hub.example-wt-b742.localhost"
    assert caddy.configs
    assert "hub.example-wt-b742.localhost" in caddy.configs[-1]

    reservation = manager.acquire_reservation("shared-model", cwd=worktree)
    assert reservation["owner_id"] == linked["owner_id"]
    with pytest.raises(ConflictError, match="owned by example-app:wt-b742"):
        manager.acquire_reservation("shared-model", cwd=primary)
    with pytest.raises(ConflictError, match="belongs to example-app:wt-b742"):
        manager.release_reservation("shared-model", cwd=primary)
    assert manager.release_reservation("shared-model", cwd=worktree)

    with pytest.raises(ConflictError, match="still has route"):
        manager.release_port("hub", cwd=worktree)
    assert manager.remove_route("hub", cwd=worktree)
    assert manager.release_port("hub", cwd=worktree)


def test_route_failure_keeps_registry_unchanged(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, caddy, store = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    port = manager.allocate_port("hub", cwd=primary)
    before = manager.status()
    caddy.fail = True
    with pytest.raises(CaddyError, match="candidate rejected"):
        manager.apply_route(
            "hub",
            hostname="hub.example.localhost",
            upstream=f"http://127.0.0.1:{port['port']}",
            port_service="hub",
            cwd=primary,
        )
    assert manager.status() == before
    assert not store.journal_path.exists()


def test_staged_route_is_validated_and_persisted_without_live_reload(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, caddy, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)

    route = manager.stage_route(
        "hub",
        hostname="hub.example.localhost",
        upstream="http://127.0.0.1:5173",
        cwd=primary,
    )

    assert route["hostname"] == "hub.example.localhost"
    assert len(caddy.configs) == 1
    assert caddy.configs[0].startswith("validated:")
    context = next(iter(manager.status()["contexts"].values()))
    assert context["routes"]["hub"] == route


def test_staged_route_validation_failure_keeps_registry_unchanged(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, caddy, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    before = manager.status()
    caddy.fail = True

    with pytest.raises(CaddyError, match="candidate rejected"):
        manager.stage_route(
            "hub",
            hostname="hub.example.localhost",
            upstream="http://127.0.0.1:5173",
            cwd=primary,
        )

    caddy.fail = False
    assert manager.status() == before


def test_identical_apply_after_stage_reconciles_live_caddy(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, caddy, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    manager.stage_route(
        "hub",
        hostname="hub.example.localhost",
        upstream="http://127.0.0.1:5173",
        cwd=primary,
    )

    manager.apply_route(
        "hub",
        hostname="hub.example.localhost",
        upstream="http://127.0.0.1:5173",
        cwd=primary,
    )

    assert len(caddy.configs) == 2
    assert caddy.configs[0].startswith("validated:")
    assert not caddy.configs[1].startswith("validated:")


def test_staging_refuses_to_drift_a_live_caddy(
    tmp_path: Path,
    checkouts: tuple[Path, Path],
    service: tuple[YanPortService, RecordingCaddy, StateStore],
) -> None:
    primary, _ = checkouts
    manager, caddy, _ = service
    caddy.admin_socket = str(tmp_path / "admin.sock")
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    Path(caddy.admin_socket).touch()

    with pytest.raises(ConflictError, match="only allowed before native Caddy is live"):
        manager.stage_route(
            "hub",
            hostname="hub.example.localhost",
            upstream="http://127.0.0.1:5173",
            cwd=primary,
        )


def test_staging_refuses_a_linked_worktree(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    _, worktree = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)

    with pytest.raises(ConflictError, match="primary Local checkout"):
        manager.stage_route(
            "hub",
            hostname="hub.example-wt-b742.localhost",
            upstream="http://127.0.0.1:5173",
            cwd=worktree,
        )


def test_unexpected_route_interruption_is_recovered_on_next_operation(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, caddy, store = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    port = manager.allocate_port("hub", cwd=primary)
    before = manager.status()
    caddy.crash = True
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        manager.apply_route(
            "hub",
            hostname="hub.example.localhost",
            upstream=f"http://127.0.0.1:{port['port']}",
            port_service="hub",
            cwd=primary,
        )
    assert store.journal_path.exists()
    assert manager.allocate_port("frontend", cwd=primary)["port"]
    assert not store.journal_path.exists()
    recovered = manager.status()
    assert recovered["generation"] == before["generation"] + 1
    assert "hub" not in next(iter(recovered["contexts"].values()))["routes"]


def test_claim_rejects_a_port_used_outside_yanport(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        with pytest.raises(ConflictError, match="outside YanPort"):
            manager.claim_port("hub", port, cwd=primary)


def test_route_port_must_match_named_lease(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    port = manager.allocate_port("hub", cwd=primary)
    with pytest.raises(ConflictError, match="does not match"):
        manager.apply_route(
            "hub",
            hostname="hub.example.localhost",
            upstream=f"http://127.0.0.1:{port['port'] + 1}",
            port_service="hub",
            cwd=primary,
        )


def test_wrong_or_missing_lease_is_rejected(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, _, store = service
    context = manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    lease_path = store.lease_path(context["owner_id"])
    payload = json.loads(lease_path.read_text())
    payload["token"] = "wrong"
    store.write(payload, path=lease_path)
    with pytest.raises(ContextError, match="do not own"):
        manager.allocate_port("hub", cwd=primary)


def test_worktree_cannot_register_main_hostname(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    _, worktree = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    with pytest.raises(ConflictError, match="outside context domain"):
        manager.apply_route(
            "hub",
            hostname="hub.example.localhost",
            upstream="http://127.0.0.1:25173",
            cwd=worktree,
        )


def test_inspect_matches_detection(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    _, worktree = checkouts
    manager, _, _ = service
    assert manager.inspect_context(worktree) == detect_context(worktree).as_dict()


def test_local_can_explicitly_release_stopped_worktree(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, worktree = checkouts
    manager, _, store = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    linked = manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    manager.allocate_port("hub", cwd=worktree)
    manager.acquire_reservation("shared-model", cwd=worktree)
    with pytest.raises(ContextError, match="requires --yes"):
        manager.release_context(target=worktree, cwd=primary)
    released = manager.release_context(target=worktree, cwd=primary, confirmed=True)
    assert released["context_id"] == "wt-b742"
    assert released["reservations"] == ["shared-model"]
    assert linked["owner_id"] not in manager.status()["contexts"]
    assert not store.lease_path(linked["owner_id"]).exists()


def test_worktree_cannot_release_another_context(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, worktree = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    with pytest.raises(ContextError, match="Only the primary Local"):
        manager.release_context(target=primary, cwd=worktree, confirmed=True)


def test_local_can_release_context_after_worktree_directory_was_deleted(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, worktree = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    linked = manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    git(primary, "worktree", "remove", "--force", str(worktree))

    released = manager.release_context(target=worktree, cwd=primary, confirmed=True)
    assert released["context_id"] == "wt-b742"
    assert linked["owner_id"] not in manager.status()["contexts"]


def test_local_can_release_stale_context_by_owner_id(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, worktree = checkouts
    manager, _, _ = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    linked = manager.ensure_context(project="example-app", domain="example.localhost", cwd=worktree)
    git(primary, "worktree", "remove", "--force", str(worktree))

    with pytest.raises(ContextError, match="requires --yes"):
        manager.release_context(owner_id=linked["owner_id"], cwd=primary)
    released = manager.release_context(owner_id=linked["owner_id"], cwd=primary, confirmed=True)
    assert released["context_id"] == "wt-b742"


def test_concurrent_processes_never_receive_the_same_port(
    checkouts: tuple[Path, Path], service: tuple[YanPortService, RecordingCaddy, StateStore]
) -> None:
    primary, _ = checkouts
    manager, _, store = service
    manager.ensure_context(project="example-app", domain="example.localhost", cwd=primary)
    process_context = multiprocessing.get_context("spawn")
    arguments = [(str(store.root), str(primary), f"service-{index}") for index in range(8)]
    with process_context.Pool(4) as pool:
        ports = pool.starmap(allocate_worker, arguments)
    assert len(ports) == len(set(ports))
    assert 25173 in ports


def test_doctor_includes_trust_problems_and_warnings(tmp_path: Path) -> None:
    trust_payload: dict[str, object] = {
        "ok": False,
        "state": "unhealthy",
        "root_ca": {"available": True, "sha256": "a" * 64},
        "system_trust": {"installed": False, "matches_active": False},
        "routes": [],
        "problems": ["system trust store does not contain the active root CA"],
        "warnings": ["embedded browser profile trust cannot be verified"],
    }
    manager = YanPortService(
        StateStore(tmp_path / "state"),
        NoopCaddy(),  # type: ignore[arg-type]
        trust=FixedTrustInspector(trust_payload),  # type: ignore[arg-type]
    )

    payload = manager.doctor()

    assert payload["ok"] is False
    assert payload["trust"] == trust_payload
    assert payload["warnings"] == ["embedded browser profile trust cannot be verified"]
    assert "system trust store does not contain" in payload["problems"][0]


def test_doctor_keeps_trust_warnings_nonfatal(tmp_path: Path) -> None:
    trust_payload: dict[str, object] = {
        "ok": True,
        "state": "healthy",
        "root_ca": {"available": True, "sha256": "a" * 64},
        "system_trust": {"installed": True, "matches_active": True},
        "routes": [],
        "problems": [],
        "warnings": ["upstream is not listening"],
    }
    manager = YanPortService(
        StateStore(tmp_path / "state"),
        NoopCaddy(),  # type: ignore[arg-type]
        trust=FixedTrustInspector(trust_payload),  # type: ignore[arg-type]
    )

    payload = manager.doctor()

    assert payload["ok"] is True
    assert payload["warnings"] == ["upstream is not listening"]
