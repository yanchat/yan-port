from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

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
