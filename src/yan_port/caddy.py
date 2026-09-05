"""Strict Caddy configuration generation and atomic reload support."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import CaddyError

_HOSTNAME = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+localhost$")


def validate_hostname(hostname: str) -> str:
    requested = hostname.strip().rstrip(".")
    if requested != requested.lower():
        raise ValueError(f"YanPort requires lowercase hostnames: {hostname!r}")
    normalized = requested
    if not _HOSTNAME.fullmatch(normalized):
        raise ValueError(f"YanPort requires an exact lowercase .localhost hostname: {hostname!r}")
    return normalized


def validate_domain(domain: str) -> str:
    normalized = validate_hostname(f"probe.{domain.strip().lower().rstrip('.')}")
    return normalized.removeprefix("probe.")


def validate_upstream(upstream: str) -> str:
    parsed = urlsplit(upstream)
    if (
        parsed.scheme != "http"
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("YanPort upstreams must be bare loopback HTTP origins")
    if parsed.query or parsed.fragment or parsed.port is None:
        raise ValueError("YanPort upstreams must include only a loopback host and port")
    hostname = parsed.hostname
    if hostname == "localhost":
        hostname = "127.0.0.1"
    try:
        address = ipaddress.ip_address(hostname or "")
    except ValueError as exc:
        raise ValueError("YanPort upstreams must use a loopback IP address") from exc
    if not address.is_loopback:
        raise ValueError("YanPort upstreams must use a loopback IP address")
    rendered_host = f"[{address}]" if address.version == 6 else str(address)
    return f"http://{rendered_host}:{parsed.port}"


def render_caddyfile(
    registry: dict[str, Any],
    *,
    admin_socket: str,
    http_port: int = 80,
    https_port: int = 443,
) -> str:
    if not 1 <= http_port <= 65535 or not 1 <= https_port <= 65535:
        raise ValueError("Caddy listener ports must be within 1..65535")
    if http_port == https_port:
        raise ValueError("Caddy HTTP and HTTPS listener ports must differ")
    lines = [
        "{",
        f"\tadmin unix/{admin_socket}|0660",
        f"\thttp_port {http_port}",
        f"\thttps_port {https_port}",
        "\tauto_https disable_redirects",
        "\tpersist_config off",
        "}",
        "",
    ]
    routes: list[dict[str, str]] = []
    for context in registry.get("contexts", {}).values():
        routes.extend(context.get("routes", {}).values())
    for route in sorted(routes, key=lambda item: item["hostname"]):
        hostname = validate_hostname(route["hostname"])
        upstream = validate_upstream(route["upstream"])
        lines.extend(
            [
                f"https://{hostname} {{",
                "\tbind 127.0.0.1 [::1]",
                "\ttls internal",
                f"\treverse_proxy {upstream}",
                "}",
                "",
                f"http://{hostname} {{",
                "\tbind 127.0.0.1 [::1]",
                f"\tredir https://{hostname}{{uri}} permanent",
                "}",
                "",
            ]
        )
    if not routes:
        lines.extend([":2018 {", "\tbind 127.0.0.1", '\trespond "YanPort ready"', "}", ""])
    return "\n".join(lines)


Runner = Callable[..., subprocess.CompletedProcess[str]]


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, *, timeout: float = 2.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.socket_path)
        except BaseException:
            connection.close()
            raise
        self.sock = connection


class CaddyController:
    def __init__(
        self,
        *,
        config_path: Path | str | None = None,
        admin_socket: str | None = None,
        root_ca_path: Path | str | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        self.config_path = Path(
            config_path or os.environ.get("YAN_PORT_CADDYFILE", "/var/lib/yan-port/Caddyfile")
        )
        self.binary = os.environ.get("YAN_PORT_CADDY_BIN", "caddy")
        self.http_port = int(os.environ.get("YAN_PORT_HTTP_PORT", "80"))
        self.https_port = int(os.environ.get("YAN_PORT_HTTPS_PORT", "443"))
        self.admin_socket = admin_socket or os.environ.get(
            "YAN_PORT_CADDY_ADMIN_SOCKET", "/run/yan-port/caddy-admin.sock"
        )
        self.root_ca_path = Path(
            root_ca_path
            or os.environ.get(
                "YAN_PORT_CADDY_ROOT_CA",
                "/var/lib/yan-port/data/caddy/pki/authorities/local/root.crt",
            )
        )
        self.runner = runner

    def render(self, registry: dict[str, Any]) -> str:
        return render_caddyfile(
            registry,
            admin_socket=self.admin_socket,
            http_port=self.http_port,
            https_port=self.https_port,
        )

    def _run(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        result = self.runner(
            list(arguments),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode != 0:
            raise CaddyError(
                result.stdout.strip() or f"Caddy command failed: {' '.join(arguments)}"
            )
        return result

    def validate(self, content: str) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".Caddyfile", delete=False) as handle:
            handle.write(content)
            candidate = Path(handle.name)
        try:
            self._run(
                [self.binary, "validate", "--config", str(candidate), "--adapter", "caddyfile"]
            )
        finally:
            candidate.unlink(missing_ok=True)

    def apply(self, content: str) -> None:
        self.validate(content)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        target_gid = (
            self.config_path.stat().st_gid
            if self.config_path.exists()
            else self.config_path.parent.stat().st_gid
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".Caddyfile", dir=self.config_path.parent, delete=False
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            candidate = Path(handle.name)
        try:
            self._run(
                [
                    self.binary,
                    "reload",
                    "--config",
                    str(candidate),
                    "--adapter",
                    "caddyfile",
                    "--address",
                    f"unix/{self.admin_socket}",
                ]
            )
            os.chown(candidate, -1, target_gid)
            candidate.chmod(0o640)
            candidate.replace(self.config_path)
            directory = os.open(self.config_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            candidate.unlink(missing_ok=True)

    def status(self) -> str:
        return self._run(["systemctl", "is-active", "yan-port-caddy.service"]).stdout.strip()

    def fetch_root_certificate(self) -> bytes:
        """Fetch Caddy's active public root without reading its private data directory."""
        connection = _UnixHTTPConnection(self.admin_socket)
        try:
            connection.request("GET", "/pki/ca/local")
            response = connection.getresponse()
            body = response.read()
        except FileNotFoundError as exc:
            raise CaddyError(f"Caddy admin socket is missing: {self.admin_socket}") from exc
        except PermissionError as exc:
            raise CaddyError(
                f"Permission denied accessing Caddy admin socket: {self.admin_socket}"
            ) from exc
        except OSError as exc:
            raise CaddyError(
                f"Cannot contact Caddy admin socket {self.admin_socket}: {exc}"
            ) from exc
        finally:
            connection.close()
        if response.status != 200:
            detail = body.decode(errors="replace").strip()
            raise CaddyError(
                f"Caddy PKI API returned HTTP {response.status}" + (f": {detail}" if detail else "")
            )
        try:
            payload = json.loads(body)
            root = payload["root_certificate"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise CaddyError(
                "Caddy PKI API returned a malformed root certificate response"
            ) from exc
        if not isinstance(root, str) or "-----BEGIN CERTIFICATE-----" not in root:
            raise CaddyError("Caddy PKI API did not return a PEM root certificate")
        return root.encode()
