"""Strict Caddy configuration generation and atomic reload support."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import platform
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
    admin_address: str | None = None,
    http_port: int = 80,
    https_port: int = 443,
    proxy_loopback_host: str | None = None,
    bind_loopback: bool = True,
) -> str:
    if not 1 <= http_port <= 65535 or not 1 <= https_port <= 65535:
        raise ValueError("Caddy listener ports must be within 1..65535")
    if http_port == https_port:
        raise ValueError("Caddy HTTP and HTTPS listener ports must differ")
    lines = [
        "{",
        f"\tadmin {admin_address or f'unix/{admin_socket}|0660'}",
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
        if proxy_loopback_host is not None:
            parsed = urlsplit(upstream)
            upstream = f"http://{proxy_loopback_host}:{parsed.port}"
        https_lines = [f"https://{hostname} {{"]
        http_lines = [f"http://{hostname} {{"]
        if bind_loopback:
            https_lines.append("\tbind 127.0.0.1 [::1]")
            http_lines.append("\tbind 127.0.0.1 [::1]")
        https_lines.extend(["\ttls internal", f"\treverse_proxy {upstream}", "}", ""])
        http_lines.extend([f"\tredir https://{hostname}{{uri}} permanent", "}", ""])
        lines.extend([*https_lines, *http_lines])
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
    driver = "native"
    service_name = "yan-port-caddy.service"
    root_ca_source = "caddy_admin_api"

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
        output = self._run(
            [
                "systemctl",
                "show",
                self.service_name,
                "--property=LoadState",
                "--property=ActiveState",
            ]
        ).stdout
        properties: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in {"LoadState", "ActiveState"} or key in properties:
                raise CaddyError("Invalid systemd router status response")
            properties[key] = value
        if set(properties) != {"LoadState", "ActiveState"}:
            raise CaddyError("Incomplete systemd router status response")
        load_state = properties["LoadState"]
        active_state = properties["ActiveState"]
        if load_state == "not-found" and active_state == "inactive":
            return "not-installed"
        if load_state != "loaded" or not re.fullmatch(r"[a-z]+(?:-[a-z]+)*", active_state):
            raise CaddyError(f"Cannot inspect router state: {load_state}/{active_state}")
        return active_state

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


DOCKER_CADDY_IMAGE = (
    "caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
)


class DockerCaddyController(CaddyController):
    """Caddy lifecycle backed by one ownership-labeled Docker container."""

    container_name = "yan-port-caddy"
    volume_name = "yan-port-caddy-data"
    driver = "docker"
    service_name = container_name
    root_ca_source = "docker_container"

    def __init__(
        self,
        *,
        state_path: Path | str | None = None,
        image: str | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        state_root = Path(
            state_path
            or os.environ.get(
                "YAN_PORT_STATE_HOME",
                Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "yan-port",
            )
        )
        self.router_path = state_root / "router"
        self.config_path = self.router_path / "Caddyfile"
        self.image = image or os.environ.get("YAN_PORT_CADDY_IMAGE", DOCKER_CADDY_IMAGE)
        self.binary = "docker"
        self.http_port = int(os.environ.get("YAN_PORT_HTTP_PORT", "80"))
        self.https_port = int(os.environ.get("YAN_PORT_HTTPS_PORT", "443"))
        self.admin_socket = "docker://yan-port-caddy"
        self.root_ca_path = Path("/data/caddy/pki/authorities/local/root.crt")
        self.runner = runner

    def render(self, registry: dict[str, Any]) -> str:
        return render_caddyfile(
            registry,
            admin_socket=self.admin_socket,
            admin_address="localhost:2019",
            http_port=self.http_port,
            https_port=self.https_port,
            proxy_loopback_host="host.docker.internal",
            bind_loopback=False,
        )

    def validate(self, content: str) -> None:
        self.router_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".Caddyfile", dir=self.router_path, delete=False
        ) as handle:
            handle.write(content)
            candidate = Path(handle.name)
        try:
            self._run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--mount",
                    f"type=bind,src={candidate},dst=/config/Caddyfile,readonly",
                    self.image,
                    "caddy",
                    "validate",
                    "--config",
                    "/config/Caddyfile",
                    "--adapter",
                    "caddyfile",
                ]
            )
        finally:
            candidate.unlink(missing_ok=True)

    def _container_details(self) -> tuple[bool, str, str]:
        result = self.runner(
            [
                "docker",
                "inspect",
                "--format",
                '{{index .Config.Labels "com.yanchat.yan-port.managed"}}'
                "|{{.State.Status}}|{{.Config.Image}}",
                self.container_name,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode != 0:
            if "No such object" in result.stdout or "No such container" in result.stdout:
                return False, "missing", ""
            raise CaddyError(result.stdout.strip() or "Cannot inspect Docker router")
        managed, status, image = [*result.stdout.strip().split("|", 2), "", ""][:3]
        if managed != "true":
            raise CaddyError(f"Container {self.container_name} exists but is not owned by YanPort")
        return True, status, image

    def _write_bootstrap(self) -> None:
        if self.config_path.exists():
            return
        self.router_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config_path.write_text(self.render({"contexts": {}}), encoding="utf-8")
        self.config_path.chmod(0o600)

    def _volume_exists(self) -> bool:
        result = self.runner(
            [
                "docker",
                "volume",
                "inspect",
                "--format",
                '{{index .Labels "com.yanchat.yan-port.managed"}}',
                self.volume_name,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode:
            if "no such volume" in result.stdout.lower():
                return False
            raise CaddyError(result.stdout.strip() or "Cannot inspect Docker router volume")
        if result.stdout.strip() != "true":
            raise CaddyError(f"Volume {self.volume_name} exists but is not owned by YanPort")
        return True

    def _validate_container_contract(self) -> None:
        result = self._run(["docker", "inspect", self.container_name])
        try:
            details = json.loads(result.stdout)[0]
            host = details["HostConfig"]
            expected_ports = {
                f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                for port in (self.http_port, self.https_port)
            }
            mounts = {mount["Destination"]: mount for mount in details["Mounts"]}
            valid = (
                details["Config"]["Image"] == self.image
                and details["Config"]["Labels"]["com.yanchat.yan-port.managed"] == "true"
                and details["Config"]["Labels"]["com.yanchat.yan-port.driver"] == "docker"
                and host["PortBindings"] == expected_ports
                and host["RestartPolicy"]["Name"] == "unless-stopped"
                and set(mounts) == {"/config", "/data"}
                and mounts["/config"]["Type"] == "bind"
                and Path(mounts["/config"]["Source"]).resolve() == self.router_path.resolve()
                and mounts["/config"]["RW"] is False
                and mounts["/data"]["Type"] == "volume"
                and mounts["/data"]["Name"] == self.volume_name
                and mounts["/data"]["RW"] is True
            )
        except ValueError, KeyError, IndexError, TypeError:
            valid = False
        if not valid:
            raise CaddyError(
                "Existing router configuration differs; inspect it before reinstalling"
            )

    def install(self) -> dict[str, Any]:
        exists, status, image = self._container_details()
        volume_exists = self._volume_exists()
        if exists:
            if image != self.image:
                raise CaddyError(
                    f"Container {self.container_name} uses {image}; expected {self.image}"
                )
            self._validate_container_contract()
            if status in {"created", "dead"}:
                self._run(["docker", "rm", "--force", self.container_name])
                exists = False
            else:
                if status != "running":
                    self._run(["docker", "start", self.container_name])
                return {"changed": status != "running", "status": "running"}

        self._write_bootstrap()
        self._run(["docker", "pull", self.image])
        if not volume_exists:
            self._run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    "com.yanchat.yan-port.managed=true",
                    self.volume_name,
                ]
            )
        self._run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                self.container_name,
                "--restart",
                "unless-stopped",
                "--label",
                "com.yanchat.yan-port.managed=true",
                "--label",
                "com.yanchat.yan-port.driver=docker",
                "--publish",
                f"127.0.0.1:{self.http_port}:{self.http_port}/tcp",
                "--publish",
                f"127.0.0.1:{self.https_port}:{self.https_port}/tcp",
                "--mount",
                f"type=bind,src={self.router_path},dst=/config,readonly",
                "--mount",
                f"type=volume,src={self.volume_name},dst=/data",
                self.image,
                "caddy",
                "run",
                "--config",
                "/config/Caddyfile",
                "--adapter",
                "caddyfile",
            ]
        )
        return {"changed": True, "status": "running"}

    def apply(self, content: str) -> None:
        self.validate(content)
        exists, status, _image = self._container_details()
        if not exists or status != "running":
            raise CaddyError("YanPort Docker router is not running; run `yan-port router install`")
        self.router_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=".Caddyfile.tmp-", dir=self.router_path, delete=False
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            candidate = Path(handle.name)
        try:
            self._run(
                [
                    "docker",
                    "exec",
                    self.container_name,
                    "caddy",
                    "reload",
                    "--config",
                    f"/config/{candidate.name}",
                    "--adapter",
                    "caddyfile",
                ]
            )
            candidate.chmod(0o600)
            candidate.replace(self.config_path)
            directory = os.open(self.router_path, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            candidate.unlink(missing_ok=True)

    def status(self) -> str:
        exists, status, _image = self._container_details()
        if not exists:
            return "not-installed"
        self._validate_container_contract()
        if not self._volume_exists():
            raise CaddyError("YanPort Docker router certificate volume is missing")
        return status

    def start(self) -> dict[str, Any]:
        exists, status, _image = self._container_details()
        if not exists:
            raise CaddyError("YanPort Docker router is not installed")
        self._validate_container_contract()
        if not self._volume_exists():
            raise CaddyError("YanPort Docker router certificate volume is missing")
        if status == "running":
            return {"changed": False, "status": status}
        self._run(["docker", "start", self.container_name])
        return {"changed": True, "status": "running"}

    def stop(self) -> dict[str, Any]:
        exists, status, _image = self._container_details()
        if not exists or status != "running":
            return {"changed": False, "status": status}
        self._validate_container_contract()
        self._run(["docker", "stop", self.container_name])
        return {"changed": True, "status": "exited"}

    def uninstall(self, *, purge_data: bool = False) -> dict[str, Any]:
        exists, _status, _image = self._container_details()
        volume_exists = self._volume_exists() if purge_data else False
        if exists:
            self._validate_container_contract()
            self._run(["docker", "rm", "--force", self.container_name])
        if purge_data and volume_exists:
            self._run(["docker", "volume", "rm", self.volume_name])
        return {"changed": exists or volume_exists, "data_preserved": not purge_data}

    def fetch_root_certificate(self) -> bytes:
        result = self._run(
            [
                "docker",
                "exec",
                self.container_name,
                "cat",
                str(self.root_ca_path),
            ]
        )
        root = result.stdout
        if "-----BEGIN CERTIFICATE-----" not in root:
            raise CaddyError("YanPort Docker router returned a malformed root certificate")
        return root.encode()


def create_caddy_controller() -> CaddyController:
    driver = os.environ.get("YAN_PORT_ROUTER_DRIVER")
    if driver is None:
        driver = "docker" if platform.system() == "Darwin" else "native"
    if driver == "native":
        return CaddyController()
    if driver == "docker":
        return DockerCaddyController()
    raise ValueError("YAN_PORT_ROUTER_DRIVER must be 'native' or 'docker'")
