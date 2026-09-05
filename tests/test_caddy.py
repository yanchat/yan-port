from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import threading
from pathlib import Path

import pytest

from yan_port.caddy import (
    CaddyController,
    render_caddyfile,
    validate_domain,
    validate_hostname,
    validate_upstream,
)
from yan_port.errors import CaddyError
from yan_port.registry import empty_registry


def test_strict_local_validation() -> None:
    assert validate_hostname("api.hub.example-wt-ac88.localhost") == (
        "api.hub.example-wt-ac88.localhost"
    )
    assert validate_domain("example.localhost") == "example.localhost"
    assert validate_upstream("http://127.0.0.1:28080") == "http://127.0.0.1:28080"
    assert validate_upstream("http://[::1]:28080") == "http://[::1]:28080"


@pytest.mark.parametrize(
    "hostname",
    ["example.com", "*.localhost", "UPPER.localhost", "localhost", "bad_name.localhost"],
)
def test_rejects_unsafe_hostnames(hostname: str) -> None:
    with pytest.raises(ValueError):
        validate_hostname(hostname)


@pytest.mark.parametrize(
    "upstream",
    [
        "https://127.0.0.1:8000",
        "http://0.0.0.0:8000",
        "http://192.168.1.4:8000",
        "http://127.0.0.1:8000/path",
        "http://user:pass@127.0.0.1:8000",
    ],
)
def test_rejects_unsafe_upstreams(upstream: str) -> None:
    with pytest.raises(ValueError):
        validate_upstream(upstream)


def test_render_has_exact_tls_proxy_and_http_redirect() -> None:
    registry = empty_registry()
    registry["contexts"]["owner"] = {
        "routes": {
            "hub": {
                "hostname": "hub.example-wt-ac88.localhost",
                "upstream": "http://127.0.0.1:28080",
            }
        }
    }
    rendered = render_caddyfile(registry, admin_socket="/run/yan-port/admin.sock")
    assert "admin unix//run/yan-port/admin.sock|0660" in rendered
    assert "https://hub.example-wt-ac88.localhost" in rendered
    assert "bind 127.0.0.1 [::1]" in rendered
    assert "tls internal" in rendered
    assert "reverse_proxy http://127.0.0.1:28080" in rendered
    assert "http://hub.example-wt-ac88.localhost" in rendered
    assert "redir https://hub.example-wt-ac88.localhost{uri} permanent" in rendered


def test_render_supports_temporary_cutover_listener_ports() -> None:
    rendered = render_caddyfile(
        empty_registry(),
        admin_socket="/tmp/admin.sock",
        http_port=18080,
        https_port=18443,
    )
    assert "http_port 18080" in rendered
    assert "https_port 18443" in rendered


@pytest.mark.parametrize("http_port,https_port", [(0, 443), (80, 65536), (443, 443)])
def test_render_rejects_invalid_listener_ports(http_port: int, https_port: int) -> None:
    with pytest.raises(ValueError):
        render_caddyfile(
            empty_registry(),
            admin_socket="/tmp/admin.sock",
            http_port=http_port,
            https_port=https_port,
        )


def test_apply_preserves_restart_readable_group_and_mode(tmp_path: Path) -> None:
    config = tmp_path / "Caddyfile"
    config.write_text("bootstrap\n")
    expected_gid = config.stat().st_gid

    def successful(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "ok", "")

    controller = CaddyController(
        config_path=config,
        admin_socket=str(tmp_path / "admin.sock"),
        runner=successful,
    )
    controller.apply("new config\n")

    metadata = config.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o640
    assert metadata.st_gid == expected_gid
    assert os.access(config, os.R_OK)


def test_service_state_directory_is_setgid() -> None:
    installer = (Path(__file__).parents[1] / "scripts" / "install-service.sh").read_text()
    assert "-m 2770 /var/lib/yan-port" in installer


def test_native_service_recovers_after_failure() -> None:
    unit = (Path(__file__).parents[1] / "deploy" / "yan-port-caddy.service").read_text()
    assert "Restart=on-failure" in unit
    assert "RestartSec=2s" in unit


def _serve_unix_response(socket_path: Path, body: bytes) -> threading.Thread:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)

    def serve() -> None:
        with listener:
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
                connection.sendall(response)

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def test_fetch_root_certificate_uses_permissioned_admin_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "admin.sock"
    root = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
    thread = _serve_unix_response(
        socket_path,
        json.dumps({"root_certificate": root}).encode(),
    )
    controller = CaddyController(admin_socket=str(socket_path))

    fetched = controller.fetch_root_certificate()
    thread.join(timeout=2)

    assert fetched == root.encode()
    assert not thread.is_alive()


def test_fetch_root_certificate_categorizes_socket_and_response_errors(tmp_path: Path) -> None:
    missing = CaddyController(admin_socket=str(tmp_path / "missing.sock"))
    with pytest.raises(CaddyError, match="admin socket is missing"):
        missing.fetch_root_certificate()

    socket_path = tmp_path / "malformed.sock"
    thread = _serve_unix_response(socket_path, b"{}")
    malformed = CaddyController(admin_socket=str(socket_path))
    with pytest.raises(CaddyError, match="malformed root certificate response"):
        malformed.fetch_root_certificate()
    thread.join(timeout=2)
