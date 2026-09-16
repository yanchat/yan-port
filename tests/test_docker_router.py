from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from yan_port.caddy import DockerCaddyController, create_caddy_controller
from yan_port.errors import CaddyError
from yan_port.registry import empty_registry


class RecordingRunner:
    def __init__(self, responses: list[subprocess.CompletedProcess[str]] | None = None) -> None:
        self.responses = list(responses or [])
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if self.responses:
            return self.responses.pop(0)
        return subprocess.CompletedProcess(command, 0, "", "")


def completed(
    command: list[str], returncode: int = 0, output: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, output, "")


def routed_registry() -> dict[str, object]:
    registry = empty_registry()
    registry["contexts"]["owner"] = {
        "routes": {
            "hub": {
                "hostname": "hub.example.localhost",
                "upstream": "http://127.0.0.1:28080",
            }
        }
    }
    return registry


def test_driver_selection_defaults_by_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("YAN_PORT_ROUTER_DRIVER", raising=False)
    monkeypatch.setattr("yan_port.caddy.platform.system", lambda: "Darwin")
    assert isinstance(create_caddy_controller(), DockerCaddyController)

    monkeypatch.setattr("yan_port.caddy.platform.system", lambda: "Linux")
    assert create_caddy_controller().__class__.__name__ == "CaddyController"


def test_driver_selection_honors_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YAN_PORT_ROUTER_DRIVER", "docker")
    assert isinstance(create_caddy_controller(), DockerCaddyController)
    monkeypatch.setenv("YAN_PORT_ROUTER_DRIVER", "unsupported")
    with pytest.raises(ValueError, match="YAN_PORT_ROUTER_DRIVER"):
        create_caddy_controller()


def test_docker_render_keeps_registry_loopback_but_proxies_to_host(tmp_path: Path) -> None:
    controller = DockerCaddyController(state_path=tmp_path, runner=RecordingRunner())

    rendered = controller.render(routed_registry())

    assert "admin localhost:2019" in rendered
    assert "reverse_proxy http://host.docker.internal:28080" in rendered
    assert "bind 127.0.0.1" not in rendered
    assert routed_registry()["contexts"]["owner"]["routes"]["hub"]["upstream"] == (
        "http://127.0.0.1:28080"
    )


def test_install_creates_owned_volume_and_loopback_container(tmp_path: Path) -> None:
    runner = RecordingRunner(
        [
            completed([], 1, "No such object: yan-port-caddy"),
            completed([], 1, "no such volume"),
            completed([]),
            completed([], 0, "volume"),
            completed([], 0, "container-id"),
        ]
    )
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)

    payload = controller.install()

    assert payload["changed"] is True
    assert (tmp_path / "router" / "Caddyfile").is_file()
    commands = [" ".join(command) for command in runner.commands]
    assert any("docker pull" in command for command in commands)
    assert any("docker volume create" in command for command in commands)
    run = next(command for command in runner.commands if command[:2] == ["docker", "run"])
    assert "127.0.0.1:80:80/tcp" in run
    assert "127.0.0.1:443:443/tcp" in run
    assert "com.yanchat.yan-port.managed=true" in run
    assert "unless-stopped" in run


def test_install_refuses_foreign_existing_container(tmp_path: Path) -> None:
    runner = RecordingRunner([completed([], 0, "false|running|sha256:other")])
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)

    with pytest.raises(CaddyError, match="not owned by YanPort"):
        controller.install()


def test_apply_validates_reloads_candidate_then_commits(tmp_path: Path, monkeypatch) -> None:
    config_dir = tmp_path / "router"
    config_dir.mkdir()
    config = config_dir / "Caddyfile"
    config.write_text("old\n")
    runner = RecordingRunner(
        [
            completed([]),
            completed([]),
        ]
    )
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    monkeypatch.setattr(controller, "status", lambda: "running")

    controller.apply("new\n")

    assert config.read_text() == "new\n"
    assert runner.commands[0][:3] == ["docker", "run", "--rm"]
    reload_command = runner.commands[1]
    assert reload_command[:4] == ["docker", "exec", "yan-port-caddy", "caddy"]
    assert any(part.startswith("/config/.") for part in reload_command)
    assert not list(config_dir.glob(".reload-*"))


def test_apply_preserves_config_when_reload_fails(tmp_path: Path, monkeypatch) -> None:
    config_dir = tmp_path / "router"
    config_dir.mkdir()
    config = config_dir / "Caddyfile"
    config.write_text("old\n")
    runner = RecordingRunner(
        [
            completed([]),
            completed([], 1, "reload failed"),
        ]
    )
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    monkeypatch.setattr(controller, "status", lambda: "running")

    with pytest.raises(CaddyError, match="reload failed"):
        controller.apply("new\n")

    assert config.read_text() == "old\n"
    assert not list(config_dir.glob(".reload-*"))


def test_fetch_root_certificate_reads_public_root_from_container(
    tmp_path: Path, monkeypatch
) -> None:
    root = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
    runner = RecordingRunner([completed([], output=root)])
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    monkeypatch.setattr(controller, "status", lambda: "running")

    assert controller.fetch_root_certificate() == root.encode()
    assert runner.commands == [
        [
            "docker",
            "exec",
            "yan-port-caddy",
            "cat",
            "/data/caddy/pki/authorities/local/root.crt",
        ]
    ]


@pytest.mark.parametrize("rollback_fails", [False, True])
@pytest.mark.parametrize("failure", ["replace", "sync"])
def test_persistence_failure_restores_previous_live_configuration(
    tmp_path, monkeypatch, rollback_fails, failure
):
    controller = DockerCaddyController(state_path=tmp_path)
    controller.router_path.mkdir()
    controller.config_path.write_text("old\n")
    monkeypatch.setattr(controller, "status", lambda: "running")
    monkeypatch.setattr(controller, "validate", lambda content: None)
    live = []

    def run(command, **kwargs):
        content = (
            controller.router_path / command[command.index("--config") + 1].removeprefix("/config/")
        ).read_text()
        if rollback_fails and content == "old\n":
            return completed(command, 1, "rollback rejected")
        live.append(content)
        return completed(command)

    controller.runner = run
    replace = Path.replace

    def fail_candidate(path, target):
        if failure == "replace" and path.read_text() == "new\n":
            raise OSError("disk failure")
        return replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_candidate)
    fsync = os.fsync
    failed_sync = False

    def fail_directory_sync(fd):
        nonlocal failed_sync
        if failure == "sync" and not failed_sync and stat.S_ISDIR(os.fstat(fd).st_mode):
            failed_sync = True
            raise OSError("directory sync failed")
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    with pytest.raises(CaddyError, match="rollback failed" if rollback_fails else "restored"):
        controller.apply("new\n")
    assert controller.config_path.read_text() == (
        "new\n" if failure == "sync" and rollback_fails else "old\n"
    )
    assert live == (["new\n"] if rollback_fails else ["new\n", "old\n"])
    staging = list(controller.router_path.glob(".reload-*"))
    assert bool(staging) is rollback_fails
    if rollback_fails:
        assert (staging[0] / "previous").read_text() == "old\n"


@pytest.mark.parametrize("operation", ["install", "uninstall"])
def test_foreign_volume_is_never_adopted_or_deleted(tmp_path: Path, operation: str) -> None:
    runner = RecordingRunner(
        [
            completed([], 1, "No such object: yan-port-caddy"),
            completed([], output="false"),
        ]
    )
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    with pytest.raises(CaddyError, match=r"Volume .* not owned"):
        if operation == "install":
            controller.install()
        else:
            controller.uninstall(purge_data=True)
    assert all(command[1:3] != ["volume", "rm"] for command in runner.commands)


def test_daemon_failure_is_not_missing_router(tmp_path: Path) -> None:
    runner = RecordingRunner([completed([], 1, "Cannot connect to the Docker daemon")])
    with pytest.raises(CaddyError, match="Cannot connect"):
        DockerCaddyController(state_path=tmp_path, runner=runner).status()


@pytest.mark.parametrize("missing", [False, True])
@pytest.mark.parametrize("operation", ["status", "apply", "fetch_root_certificate"])
def test_status_refuses_missing_or_foreign_certificate_volume(
    tmp_path, monkeypatch, missing, operation
):
    runner = RecordingRunner(
        [
            completed([], 1, "No such volume") if missing else completed([], output="false"),
        ]
    )
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    monkeypatch.setattr(
        controller, "_container_details", lambda: (True, "running", controller.image)
    )
    monkeypatch.setattr(controller, "_validate_container_contract", lambda: None)
    with pytest.raises(CaddyError, match="volume is missing" if missing else "not owned"):
        getattr(controller, operation)(*("new\n",) if operation == "apply" else ())
    assert all(command[:3] == ["docker", "volume", "inspect"] for command in runner.commands)


@pytest.mark.parametrize("state", ["not-installed", "exited", "paused"])
@pytest.mark.parametrize("operation", ["apply", "fetch_root_certificate"])
def test_reload_and_certificate_export_require_running_router(
    tmp_path, monkeypatch, state, operation
):
    runner = RecordingRunner()
    controller = DockerCaddyController(state_path=tmp_path, runner=runner)
    monkeypatch.setattr(controller, "status", lambda: state)
    with pytest.raises(CaddyError, match="not running"):
        getattr(controller, operation)(*("new\n",) if operation == "apply" else ())
    assert runner.commands == []


@pytest.mark.parametrize("status", ["running", "exited", "created", "dead"])
def test_install_refuses_existing_container_contract_drift(tmp_path: Path, status: str) -> None:
    controller = DockerCaddyController(state_path=tmp_path)
    controller.runner = RecordingRunner(
        [
            completed([], output=f"true|{status}|{controller.image}"),
            completed([], output="true"),
            completed([], output=json.dumps([{"HostConfig": {"PortBindings": {}}}])),
        ]
    )
    with pytest.raises(CaddyError, match="configuration differs"):
        controller.install()
    assert not any(command[1] in {"start", "rm", "run"} for command in controller.runner.commands)


@pytest.mark.parametrize("operation", ["start", "stop", "uninstall"])
def test_router_lifecycle_refuses_configuration_drift(tmp_path: Path, operation: str) -> None:
    controller = DockerCaddyController(state_path=tmp_path)
    runner = RecordingRunner(
        [
            completed([], output=f"true|running|{controller.image}"),
            completed([], output=json.dumps([{"HostConfig": {"PortBindings": {}}}])),
        ]
    )
    controller.runner = runner
    with pytest.raises(CaddyError, match="configuration differs"):
        getattr(controller, operation)()
    assert all(command[1] == "inspect" for command in runner.commands)


@pytest.mark.parametrize(
    "operation",
    ["install", "start", "stop", "uninstall", "status", "apply", "fetch_root_certificate"],
)
@pytest.mark.parametrize("drift", [None, "image", "driver", "mount", "readonly"])
def test_lifecycle_accepts_only_complete_owned_contract(
    tmp_path: Path, operation: str, drift
) -> None:
    controller = DockerCaddyController(state_path=tmp_path)
    details = {
        "Config": {
            "Image": controller.image,
            "Labels": {
                "com.yanchat.yan-port.managed": "true",
                "com.yanchat.yan-port.driver": "docker",
            },
        },
        "HostConfig": {
            "PortBindings": {
                f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                for port in (80, 443)
            },
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "Mounts": [
            {
                "Destination": "/config",
                "Type": "bind",
                "Source": str(controller.router_path),
                "RW": False,
            },
            {"Destination": "/data", "Type": "volume", "Name": controller.volume_name, "RW": True},
        ],
    }
    if drift == "image":
        details["Config"]["Image"] = "different-image"
    elif drift == "driver":
        details["Config"]["Labels"]["com.yanchat.yan-port.driver"] = "other"
    elif drift == "mount":
        details["Mounts"].append({"Destination": "/foreign"})
    elif drift == "readonly":
        details["Mounts"][0]["RW"] = True
    responses = [completed([], output=f"true|running|{controller.image}")]
    if operation == "install":
        responses.append(completed([], output="true"))
    responses.append(completed([], output=json.dumps([details])))
    if operation in {"start", "status", "apply", "fetch_root_certificate"}:
        responses.append(completed([], output="true"))
    if operation == "fetch_root_certificate":
        responses.append(completed([], output="-----BEGIN CERTIFICATE-----\ntest\n"))
    runner = RecordingRunner(responses)
    controller.runner = runner
    if operation == "apply":
        controller.router_path.mkdir()
        controller.config_path.write_text("old\n")
    arguments = ("new\n",) if operation == "apply" else ()
    if drift:
        with pytest.raises(CaddyError, match="configuration differs"):
            getattr(controller, operation)(*arguments)
        assert not any(
            command[1] in {"start", "stop", "rm", "run", "exec"} for command in runner.commands
        )
    else:
        result = getattr(controller, operation)(*arguments)
        if operation == "status":
            assert result == "running"
        elif operation == "apply":
            assert controller.config_path.read_text() == "new\n"
        elif operation == "fetch_root_certificate":
            assert result.startswith(b"-----BEGIN CERTIFICATE-----")
        else:
            assert result["changed"] == (operation in {"stop", "uninstall"})


def test_cli_custom_ports_keep_docker_upstream_translation(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from typer.testing import CliRunner

    from yan_port import cli

    controller = DockerCaddyController(state_path=tmp_path)
    monkeypatch.setattr(
        cli,
        "_service",
        lambda: SimpleNamespace(
            caddy=controller,
            status=routed_registry,
        ),
    )
    result = CliRunner().invoke(
        cli.app, ["router", "render", "--http-port", "8088", "--https-port", "8443"]
    )
    assert result.exit_code == 0, result.output
    assert "http_port 8088" in result.output
    assert "host.docker.internal" in result.output
    assert "unix/" not in result.output
