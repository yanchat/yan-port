"""Local Caddy certificate trust inspection and safe public-root export."""

from __future__ import annotations

import os
import socket
import ssl
import stat
import tempfile
import warnings
from collections.abc import Callable, Iterable
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ExtensionOID

from .caddy import validate_hostname
from .errors import CaddyError, TrustError

_BROWSER_WARNING = (
    "System trust is healthy, but Chromium/Electron/Codex profiles may use separate trust storage."
)


class TrustCaddy(Protocol):
    root_ca_path: Path
    https_port: int

    def fetch_root_certificate(self) -> bytes: ...


RouteProbe = Callable[[str, str, bytes, int], dict[str, Any]]


def load_certificate(data: bytes) -> x509.Certificate:
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise TrustError("malformed certificate data") from exc


def certificate_sha256(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def certificate_dns_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return []
    return list(extension.value.get_values_for_type(x509.DNSName))


def _certificates_in_data(data: bytes) -> list[x509.Certificate]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            if b"-----BEGIN CERTIFICATE-----" in data:
                return list(x509.load_pem_x509_certificates(data))
            return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def _default_system_store_paths() -> tuple[Path, ...]:
    defaults = ssl.get_default_verify_paths()
    candidates = [defaults.cafile, defaults.capath, "/etc/ssl/certs/ca-certificates.crt"]
    paths: list[Path] = []
    for candidate in candidates:
        if candidate is None:
            continue
        path = Path(candidate)
        if path not in paths:
            paths.append(path)
    return tuple(paths)


def _store_contains(fingerprint: str, paths: Iterable[Path]) -> bool:
    visited: set[tuple[int, int]] = set()
    for location in paths:
        try:
            candidates = tuple(location.iterdir()) if location.is_dir() else (location,)
        except OSError:
            continue
        for candidate in candidates:
            try:
                metadata = candidate.stat()
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in visited or not stat.S_ISREG(metadata.st_mode):
                    continue
                visited.add(identity)
                data = candidate.read_bytes()
            except OSError:
                continue
            if any(certificate_sha256(cert) == fingerprint for cert in _certificates_in_data(data)):
                return True
    return False


def _connect_tls(hostname: str, https_port: int, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw = socket.create_connection(("127.0.0.1", https_port), timeout=2.0)
    try:
        return context.wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def _upstream_listening(upstream: str) -> tuple[bool, str | None]:
    parsed = urlsplit(upstream)
    try:
        with socket.create_connection((parsed.hostname or "", parsed.port or 0), timeout=0.5):
            return True, None
    except OSError as exc:
        return False, str(exc)


def probe_route(hostname: str, upstream: str, root_pem: bytes, https_port: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hostname": hostname,
        "tls_reachable": False,
        "leaf_sha256": None,
        "san_dns_names": [],
        "san_matches": False,
        "chains_to_active_root": False,
        "system_trusted": False,
        "upstream": upstream,
        "upstream_listening": False,
        "errors": {
            "tls": None,
            "chain": None,
            "hostname": None,
            "system_trust": None,
            "upstream": None,
        },
        "problems": [],
        "warnings": [],
    }

    upstream_ok, upstream_error = _upstream_listening(upstream)
    result["upstream_listening"] = upstream_ok
    if not upstream_ok:
        message = f"upstream is not listening: {upstream}"
        result["errors"]["upstream"] = upstream_error
        result["warnings"].append(message)

    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        with _connect_tls(hostname, https_port, unverified) as connection:
            chain = connection.get_unverified_chain()
    except (OSError, ssl.SSLError) as exc:
        message = f"TLS handshake failed for {hostname}: {exc}"
        result["errors"]["tls"] = str(exc)
        result["problems"].append(message)
        return result

    result["tls_reachable"] = True
    try:
        leaf = load_certificate(bytes(chain[0]))
    except (IndexError, TrustError) as exc:
        message = f"Caddy did not present a valid leaf certificate for {hostname}: {exc}"
        result["errors"]["tls"] = str(exc)
        result["problems"].append(message)
        return result
    result["leaf_sha256"] = certificate_sha256(leaf)
    sans = certificate_dns_names(leaf)
    result["san_dns_names"] = sans
    result["san_matches"] = hostname in sans
    if not result["san_matches"]:
        message = f"leaf certificate SAN does not contain {hostname}"
        result["errors"]["hostname"] = message
        result["problems"].append(message)

    active_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    active_context.check_hostname = False
    active_context.verify_mode = ssl.CERT_REQUIRED
    try:
        active_context.load_verify_locations(cadata=root_pem.decode())
        with _connect_tls(hostname, https_port, active_context):
            pass
        result["chains_to_active_root"] = True
    except (OSError, ssl.SSLError, UnicodeDecodeError) as exc:
        message = f"leaf certificate does not chain to the active root for {hostname}: {exc}"
        result["errors"]["chain"] = str(exc)
        result["problems"].append(message)

    system_context = ssl.create_default_context()
    try:
        with _connect_tls(hostname, https_port, system_context):
            pass
        result["system_trusted"] = True
    except (OSError, ssl.SSLError) as exc:
        message = f"system TLS verification failed for {hostname}: {exc}"
        result["errors"]["system_trust"] = str(exc)
        result["problems"].append(message)
    return result


class TrustInspector:
    def __init__(
        self,
        caddy: TrustCaddy,
        *,
        system_anchor_path: Path | str | None = None,
        system_store_paths: Iterable[Path | str] | None = None,
        route_probe: RouteProbe = probe_route,
    ) -> None:
        self.caddy = caddy
        self.system_anchor_path = Path(
            system_anchor_path
            or os.environ.get(
                "YAN_PORT_SYSTEM_CA_ANCHOR",
                "/usr/local/share/ca-certificates/yan-port-local-root.crt",
            )
        )
        configured_paths = (
            system_store_paths if system_store_paths is not None else _default_system_store_paths()
        )
        self.system_store_paths = tuple(Path(path) for path in configured_paths)
        self.route_probe = route_probe

    @staticmethod
    def _routes(registry: dict[str, Any]) -> list[dict[str, Any]]:
        routes = [
            route
            for context in registry.get("contexts", {}).values()
            for route in context.get("routes", {}).values()
        ]
        return sorted(routes, key=lambda route: str(route["hostname"]))

    def _empty_status(self) -> dict[str, Any]:
        anchor_sha256: str | None = None
        if self.system_anchor_path.is_file():
            with suppress(OSError, TrustError):
                anchor_sha256 = certificate_sha256(
                    load_certificate(self.system_anchor_path.read_bytes())
                )
        return {
            "ok": True,
            "state": "not_applicable",
            "root_ca": {
                "path": str(self.caddy.root_ca_path),
                "source": None,
                "available": False,
                "sha256": None,
            },
            "system_trust": {
                "anchor_path": str(self.system_anchor_path),
                "anchor_sha256": anchor_sha256,
                "installed": False,
                "matches_active": False,
            },
            "routes": [],
            "warnings": ["No registered HTTPS routes; local CA trust is not applicable."],
            "problems": [],
        }

    def _active_root(self) -> tuple[bytes, x509.Certificate]:
        root = load_certificate(self.caddy.fetch_root_certificate())
        try:
            constraints = root.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise TrustError("active Caddy root certificate has no CA basic constraint") from exc
        if not constraints.ca:
            raise TrustError("active Caddy root certificate is not a CA")
        return root.public_bytes(serialization.Encoding.PEM), root

    def status(self, registry: dict[str, Any], *, hostname: str | None = None) -> dict[str, Any]:
        routes = self._routes(registry)
        if hostname is not None:
            normalized = validate_hostname(hostname)
            routes = [route for route in routes if route["hostname"] == normalized]
            if not routes:
                raise TrustError(f"{normalized} is not a registered YanPort route")
        if not routes:
            return self._empty_status()

        root_details = {
            "path": str(self.caddy.root_ca_path),
            "source": "caddy_admin_api",
            "available": False,
            "sha256": None,
        }
        system_details = {
            "anchor_path": str(self.system_anchor_path),
            "anchor_sha256": None,
            "installed": False,
            "matches_active": False,
        }
        problems: list[str] = []
        warnings: list[str] = []
        try:
            root_pem, root = self._active_root()
        except (CaddyError, TrustError) as exc:
            problems.append(str(exc))
            return {
                "ok": False,
                "state": "unhealthy",
                "root_ca": root_details,
                "system_trust": system_details,
                "routes": [],
                "warnings": warnings,
                "problems": problems,
            }

        active_sha256 = certificate_sha256(root)
        root_details["available"] = True
        root_details["sha256"] = active_sha256

        if not self.system_anchor_path.exists():
            problems.append(f"system CA anchor is missing: {self.system_anchor_path}")
        elif not self.system_anchor_path.is_file():
            problems.append(f"system CA anchor is not a regular file: {self.system_anchor_path}")
        else:
            try:
                anchor = load_certificate(self.system_anchor_path.read_bytes())
                anchor_sha256 = certificate_sha256(anchor)
                system_details["anchor_sha256"] = anchor_sha256
                system_details["matches_active"] = anchor_sha256 == active_sha256
                if anchor_sha256 != active_sha256:
                    problems.append("system CA anchor differs from the active Caddy root CA")
            except OSError as exc:
                problems.append(f"cannot read system CA anchor {self.system_anchor_path}: {exc}")
            except TrustError:
                problems.append(f"system CA anchor is malformed: {self.system_anchor_path}")

        installed = _store_contains(active_sha256, self.system_store_paths)
        system_details["installed"] = installed
        if not installed:
            problems.append("system trust store does not contain the active root CA")

        route_results = [
            self.route_probe(
                str(route["hostname"]),
                str(route["upstream"]),
                root_pem,
                int(self.caddy.https_port),
            )
            for route in routes
        ]
        for result in route_results:
            problems.extend(str(problem) for problem in result.get("problems", []))
            warnings.extend(str(warning) for warning in result.get("warnings", []))
        if (
            installed
            and route_results
            and all(result.get("system_trusted") for result in route_results)
        ):
            warnings.append(_BROWSER_WARNING)
        return {
            "ok": not problems,
            "state": "healthy" if not problems else "unhealthy",
            "root_ca": root_details,
            "system_trust": system_details,
            "routes": route_results,
            "warnings": warnings,
            "problems": problems,
        }

    def export(
        self, registry: dict[str, Any], output: Path | str, *, force: bool = False
    ) -> dict[str, Any]:
        if not self._routes(registry):
            raise TrustError(
                "YanPort has no HTTPS routes; apply a route before exporting its active CA"
            )
        root_pem, root = self._active_root()
        active_sha256 = certificate_sha256(root)
        destination = Path(output)
        if destination.is_symlink():
            raise TrustError(f"Refusing symbolic link output: {destination}")
        replaced_sha256: str | None = None
        if destination.exists():
            if not destination.is_file():
                raise TrustError(f"Export output is not a regular file: {destination}")
            try:
                existing_data = destination.read_bytes()
            except OSError as exc:
                raise TrustError(
                    f"Cannot read existing export output {destination}: {exc}"
                ) from exc
            if existing_data == root_pem:
                return {
                    "output": str(destination.resolve()),
                    "sha256": active_sha256,
                    "changed": False,
                    "replaced_sha256": active_sha256,
                }
            try:
                replaced_sha256 = certificate_sha256(load_certificate(existing_data))
            except TrustError:
                replaced_sha256 = None
            if not force:
                existing = replaced_sha256 or "unparseable"
                raise TrustError(
                    f"{destination} already contains different content "
                    f"({existing}); active root is {active_sha256}; use --force to replace it"
                )
        parent = destination.parent.resolve()
        if not parent.is_dir():
            raise TrustError(f"Export directory does not exist: {destination.parent}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.tmp-", dir=parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(root_pem)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o644)
            temporary.replace(destination)
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return {
            "output": str(destination.resolve()),
            "sha256": active_sha256,
            "changed": True,
            "replaced_sha256": replaced_sha256,
        }
