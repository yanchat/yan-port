from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import yan_port.cli as cli
from yan_port.cli import app

runner = CliRunner()


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
