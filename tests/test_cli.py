from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import yan_port.cli as cli
from yan_port.cli import app

runner = CliRunner()


@pytest.mark.parametrize(
    "source",
    [
        None,
        {"url": "file:///source", "dir_info": {"editable": True}},
        {
            "url": "https://github.com/yanchat/yan-port.git",
            "vcs_info": {"vcs": "git", "commit_id": "a" * 40},
        },
    ],
)
def test_version_reports_installed_metadata_without_router(monkeypatch, source):
    from types import SimpleNamespace

    monkeypatch.setattr(
        cli,
        "distribution",
        lambda name: SimpleNamespace(
            version="0.1.0",
            read_text=lambda filename: json.dumps(source) if source is not None else None,
        ),
        raising=False,
    )
    monkeypatch.setattr(cli, "_service", lambda: pytest.fail("version touched router"))
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == {"version": "0.1.0", "source": source}


@pytest.mark.parametrize(
    "command,failure",
    [
        ("provision-native", None),
        ("provision-native", 1),
        ("provision-native", 2),
        ("provision-native", 3),
        ("activate-native", None),
        ("activate-native", 1),
    ],
)
def test_native_provisioning_uses_packaged_scripts_and_stops_on_failure(
    tmp_path, monkeypatch, failure, command
):
    package = tmp_path / "package with spaces"
    assets = package / "native"
    names = (
        "scripts/install-service.sh",
        "scripts/install-caddy-binary.sh",
        "scripts/activate-service.sh",
        "deploy/bootstrap.Caddyfile",
        "deploy/yan-port-caddy.service",
        "deploy/yan-port-caddy-cutover.service",
    )
    for name in names:
        target = assets / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture")
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "_SYSTEMD_RUNTIME", tmp_path)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.shutil, "which", lambda command: f"/usr/bin/{command}")
    calls = []

    def run(command, *, check):
        assert check is True
        calls.append(command)
        if len(calls) == failure:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(cli.subprocess, "run", run)
    result = runner.invoke(app, ["router", command, "--yes"])
    assert result.exit_code == (1 if failure else 0), result.output
    expected = [
        ["sudo", "--", "/bin/bash", str(assets / "scripts/install-service.sh"), "--check"],
        ["sudo", "--", "/bin/bash", str(assets / "scripts/install-caddy-binary.sh")],
        ["sudo", "--", "/bin/bash", str(assets / "scripts/install-service.sh")],
    ]
    if command == "activate-native":
        expected = [
            ["sudo", "--", "/bin/bash", str(assets / "scripts/activate-service.sh"), "--yes"]
        ]
    assert calls == expected[:failure] if failure else calls == expected
    if failure is None and command == "provision-native":
        assert "not started" in result.output


@pytest.mark.parametrize("command", ["provision-native", "activate-native"])
def test_native_provisioning_requires_explicit_approval(monkeypatch, command):
    monkeypatch.setattr(cli, "_run_native_scripts", lambda: pytest.fail("unapproved provisioning"))
    result = runner.invoke(app, ["router", command])
    assert result.exit_code == 1
    assert "pass --yes" in result.output


@pytest.mark.parametrize(
    "defect", ["platform", "architecture", "root", "systemd", "tools", "assets"]
)
def test_native_provisioning_preflight_never_invokes_sudo(tmp_path, monkeypatch, defect):
    monkeypatch.setattr(
        cli.platform, "system", lambda: "Darwin" if defect == "platform" else "Linux"
    )
    monkeypatch.setattr(
        cli.platform, "machine", lambda: "arm64" if defect == "architecture" else "x86_64"
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0 if defect == "root" else 1000)
    monkeypatch.setattr(
        cli, "_SYSTEMD_RUNTIME", tmp_path / "absent" if defect == "systemd" else tmp_path
    )
    monkeypatch.setattr(
        cli.shutil, "which", lambda command: None if defect == "tools" else f"/usr/bin/{command}"
    )
    if defect == "assets":
        monkeypatch.setattr(cli, "__file__", str(tmp_path / "missing" / "package" / "cli.py"))
    monkeypatch.setattr(
        cli.subprocess, "run", lambda *args, **kwargs: pytest.fail("unexpected sudo")
    )
    result = runner.invoke(app, ["router", "provision-native", "--yes"])
    assert result.exit_code == 1
    assert "error:" in result.output


def git(cwd: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)


def test_context_cli_uses_json_contract(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    git(project, "init", "-b", "main")
    monkeypatch.setenv("YAN_PORT_STATE_HOME", str(tmp_path / "state"))
    result = runner.invoke(
        app,
        [
            "context",
            "ensure",
            "--project",
            "example-app",
            "--domain",
            "example.localhost",
            "--cwd",
            str(project),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["context_id"] == "main"
    assert payload["project"] == "example-app"


def test_cli_reports_expected_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("YAN_PORT_STATE_HOME", str(tmp_path / "state"))
    result = runner.invoke(app, ["context", "inspect", "--cwd", str(tmp_path)])
    assert result.exit_code == 1
    assert "error: Cannot identify YanPort context" in result.output


def test_router_render_accepts_cutover_ports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("YAN_PORT_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("YAN_PORT_ROUTER_DRIVER", "native")
    result = runner.invoke(
        app,
        [
            "router",
            "render",
            "--http-port",
            "18080",
            "--https-port",
            "18443",
            "--admin-socket",
            "/tmp/cutover.sock",
        ],
    )
    assert result.exit_code == 0
    assert "admin unix//tmp/cutover.sock|0660" in result.stdout
    assert "http_port 18080" in result.stdout
    assert "https_port 18443" in result.stdout


class FakeTrustService:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requested_hostname: str | None = None
        self.exported: tuple[Path, bool] | None = None

    def trust_status(self, hostname: str | None = None) -> dict[str, object]:
        self.requested_hostname = hostname
        return self.payload

    def trust_export(self, output: Path, *, force: bool = False) -> dict[str, object]:
        self.exported = (output, force)
        return {
            "output": str(output.resolve()),
            "sha256": "ab" * 32,
            "changed": True,
            "replaced_sha256": None,
        }


def healthy_trust_payload() -> dict[str, object]:
    return {
        "ok": True,
        "state": "healthy",
        "root_ca": {
            "path": "/var/lib/yan-port/data/caddy/pki/authorities/local/root.crt",
            "source": "caddy_admin_api",
            "available": True,
            "sha256": "ab" * 32,
        },
        "system_trust": {
            "anchor_path": "/usr/local/share/ca-certificates/yan-port-local-root.crt",
            "anchor_sha256": "ab" * 32,
            "installed": True,
            "matches_active": True,
        },
        "routes": [
            {
                "hostname": "studio.example.localhost",
                "tls_reachable": True,
                "leaf_sha256": "cd" * 32,
                "san_dns_names": ["studio.example.localhost"],
                "san_matches": True,
                "chains_to_active_root": True,
                "system_trusted": True,
                "upstream": "http://127.0.0.1:29734",
                "upstream_listening": True,
                "problems": [],
                "warnings": [],
            }
        ],
        "warnings": [
            "System trust is healthy, but Chromium/Electron/Codex profiles may use "
            "separate trust storage."
        ],
        "problems": [],
    }


def test_trust_status_json_selects_host_and_preserves_exit_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = FakeTrustService(healthy_trust_payload())
    monkeypatch.setattr(cli, "_service", lambda: service)

    result = runner.invoke(
        app,
        ["trust", "status", "--host", "studio.example.localhost", "--json"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["state"] == "healthy"
    assert service.requested_hostname == "studio.example.localhost"


def test_trust_status_human_output_formats_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = FakeTrustService(healthy_trust_payload())
    monkeypatch.setattr(cli, "_service", lambda: service)

    result = runner.invoke(app, ["trust", "status"])

    assert result.exit_code == 0, result.output
    assert "Trust state: healthy" in result.output
    assert "AB:AB:AB:AB" in result.output
    assert "studio.example.localhost" in result.output
    assert "Chromium/Electron/Codex" in result.output


def test_trust_status_failure_emits_json_before_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = healthy_trust_payload()
    payload["ok"] = False
    payload["state"] = "unhealthy"
    payload["problems"] = ["system trust store does not contain the active root CA"]
    service = FakeTrustService(payload)
    monkeypatch.setattr(cli, "_service", lambda: service)

    result = runner.invoke(app, ["trust", "status", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False


def test_trust_export_passes_safe_overwrite_choice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    service = FakeTrustService(healthy_trust_payload())
    monkeypatch.setattr(cli, "_service", lambda: service)
    output = tmp_path / "root.crt"

    result = runner.invoke(
        app,
        ["trust", "export", "--output", str(output), "--force"],
    )

    assert result.exit_code == 0, result.output
    assert service.exported == (output, True)
    assert "AB:AB:AB:AB" in result.output
