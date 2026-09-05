from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from yan_port.errors import TrustError
from yan_port.trust import (
    TrustInspector,
    certificate_dns_names,
    certificate_sha256,
    load_certificate,
    probe_route,
)


def make_ca(common_name: str = "YanPort Test Root") -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def make_leaf(hostnames: list[str]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname) for hostname in hostnames]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def make_server_chain(hostname: str) -> tuple[bytes, bytes, bytes]:
    now = dt.datetime.now(dt.UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "YanPort Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "YanPort Intermediate")])
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(intermediate_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(intermediate_key, hashes.SHA256())
    )
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    chain_pem = leaf.public_bytes(serialization.Encoding.PEM) + intermediate.public_bytes(
        serialization.Encoding.PEM
    )
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return root_pem, chain_pem, key_pem


def start_tls_server(
    tmp_path: Path, chain_pem: bytes, key_pem: bytes, connections: int
) -> tuple[int, threading.Thread]:
    certificate_path = tmp_path / "server-chain.pem"
    key_path = tmp_path / "server-key.pem"
    certificate_path.write_bytes(chain_pem)
    key_path.write_bytes(key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = int(listener.getsockname()[1])

    def serve() -> None:
        with listener:
            for _ in range(connections):
                connection, _address = listener.accept()
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except ssl.SSLError:
                    connection.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return port, thread


class FakeCaddy:
    root_ca_path = Path("/var/lib/yan-port/data/caddy/pki/authorities/local/root.crt")
    https_port = 443

    def __init__(self, root: bytes) -> None:
        self.root = root
        self.fetches = 0

    def fetch_root_certificate(self) -> bytes:
        self.fetches += 1
        return self.root


def registry(*routes: dict[str, Any]) -> dict[str, Any]:
    return {
        "contexts": {
            "owner": {
                "routes": {route["service"]: route for route in routes},
            }
        }
    }


def healthy_route_probe(
    hostname: str, upstream: str, _root_pem: bytes, _https_port: int
) -> dict[str, Any]:
    return {
        "hostname": hostname,
        "tls_reachable": True,
        "leaf_sha256": "1" * 64,
        "san_dns_names": [hostname],
        "san_matches": True,
        "chains_to_active_root": True,
        "system_trusted": True,
        "upstream": upstream,
        "upstream_listening": True,
        "problems": [],
        "warnings": [],
    }


def test_certificate_parsing_fingerprint_and_sans() -> None:
    root = make_ca()
    leaf = make_leaf(["studio.example.localhost", "alt.example.localhost"])

    assert len(certificate_sha256(load_certificate(root))) == 64
    assert certificate_dns_names(load_certificate(leaf)) == [
        "studio.example.localhost",
        "alt.example.localhost",
    ]
    with pytest.raises(TrustError, match="malformed certificate"):
        load_certificate(b"not a certificate")


def test_route_probe_separates_chain_hostname_system_and_upstream(tmp_path: Path) -> None:
    hostname = "studio.example.localhost"
    root, chain, key = make_server_chain(hostname)
    tls_port, thread = start_tls_server(tmp_path, chain, key, connections=9)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen()
        upstream_url = f"http://127.0.0.1:{upstream.getsockname()[1]}"

        healthy = probe_route(hostname, upstream_url, root, tls_port)
        wrong_root = probe_route(hostname, upstream_url, make_ca("Wrong Root"), tls_port)
        wrong_host = probe_route("other.example.localhost", upstream_url, root, tls_port)

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert healthy["tls_reachable"] is True
    assert healthy["chains_to_active_root"] is True
    assert healthy["san_matches"] is True
    assert healthy["system_trusted"] is False
    assert healthy["upstream_listening"] is True
    assert wrong_root["chains_to_active_root"] is False
    assert wrong_host["chains_to_active_root"] is True
    assert wrong_host["san_matches"] is False


def test_empty_registry_does_not_fetch_or_initialize_ca(tmp_path: Path) -> None:
    caddy = FakeCaddy(make_ca())
    inspector = TrustInspector(
        caddy,
        system_anchor_path=tmp_path / "anchor.crt",
        system_store_paths=(tmp_path / "certs",),
        route_probe=healthy_route_probe,
    )

    payload = inspector.status(registry())

    assert payload["ok"] is True
    assert payload["state"] == "not_applicable"
    assert payload["root_ca"]["available"] is False
    assert payload["routes"] == []
    assert caddy.fetches == 0


def test_status_reports_active_root_system_store_and_routes(tmp_path: Path) -> None:
    root = make_ca()
    anchor = tmp_path / "yan-port-local-root.crt"
    anchor.write_bytes(root)
    store = tmp_path / "certs"
    store.mkdir()
    (store / "active.pem").write_bytes(root)
    caddy = FakeCaddy(root)
    inspector = TrustInspector(
        caddy,
        system_anchor_path=anchor,
        system_store_paths=(store,),
        route_probe=healthy_route_probe,
    )
    state = registry(
        {
            "service": "studio",
            "hostname": "studio.example.localhost",
            "upstream": "http://127.0.0.1:29734",
        }
    )

    payload = inspector.status(state)

    fingerprint = certificate_sha256(load_certificate(root))
    assert payload["ok"] is True
    assert payload["state"] == "healthy"
    assert payload["root_ca"] == {
        "path": str(caddy.root_ca_path),
        "source": "caddy_admin_api",
        "available": True,
        "sha256": fingerprint,
    }
    assert payload["system_trust"]["installed"] is True
    assert payload["system_trust"]["matches_active"] is True
    assert payload["routes"][0]["hostname"] == "studio.example.localhost"
    assert any("Chromium" in warning for warning in payload["warnings"])


def test_status_detects_stale_anchor_and_host_selection(tmp_path: Path) -> None:
    root = make_ca("Active")
    stale = make_ca("Stale")
    anchor = tmp_path / "yan-port-local-root.crt"
    anchor.write_bytes(stale)
    caddy = FakeCaddy(root)
    inspector = TrustInspector(
        caddy,
        system_anchor_path=anchor,
        system_store_paths=(tmp_path / "certs",),
        route_probe=healthy_route_probe,
    )
    state = registry(
        {
            "service": "api",
            "hostname": "api.example.localhost",
            "upstream": "http://127.0.0.1:20001",
        },
        {
            "service": "studio",
            "hostname": "studio.example.localhost",
            "upstream": "http://127.0.0.1:20002",
        },
    )

    payload = inspector.status(state, hostname="studio.example.localhost")

    assert payload["ok"] is False
    assert [route["hostname"] for route in payload["routes"]] == ["studio.example.localhost"]
    assert payload["system_trust"]["matches_active"] is False
    assert any("differs from the active" in problem for problem in payload["problems"])
    with pytest.raises(TrustError, match="not a registered YanPort route"):
        inspector.status(state, hostname="missing.example.localhost")


def test_status_detects_missing_anchor_even_when_effective_store_has_root(tmp_path: Path) -> None:
    root = make_ca()
    store = tmp_path / "certs"
    store.mkdir()
    (store / "root.pem").write_bytes(root)
    missing_anchor = tmp_path / "missing-anchor.crt"
    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=missing_anchor,
        system_store_paths=(store,),
        route_probe=healthy_route_probe,
    )

    payload = inspector.status(
        registry(
            {
                "service": "studio",
                "hostname": "studio.example.localhost",
                "upstream": "http://127.0.0.1:29734",
            }
        )
    )

    assert payload["ok"] is False
    assert payload["system_trust"]["installed"] is True
    assert payload["system_trust"]["matches_active"] is False
    assert any("system CA anchor is missing" in problem for problem in payload["problems"])


def test_stopped_upstream_is_warning_only(tmp_path: Path) -> None:
    root = make_ca()
    anchor = tmp_path / "root.crt"
    anchor.write_bytes(root)
    store = tmp_path / "certs"
    store.mkdir()
    (store / "root.pem").write_bytes(root)

    def stopped_probe(
        hostname: str, upstream: str, root_pem: bytes, https_port: int
    ) -> dict[str, Any]:
        payload = healthy_route_probe(hostname, upstream, root_pem, https_port)
        payload["upstream_listening"] = False
        payload["warnings"] = [f"upstream is not listening: {upstream}"]
        return payload

    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=anchor,
        system_store_paths=(store,),
        route_probe=stopped_probe,
    )
    payload = inspector.status(
        registry(
            {
                "service": "studio",
                "hostname": "studio.example.localhost",
                "upstream": "http://127.0.0.1:29734",
            }
        )
    )

    assert payload["ok"] is True
    assert payload["routes"][0]["upstream_listening"] is False
    assert any("not listening" in warning for warning in payload["warnings"])


def test_default_status_sorts_all_routes_and_keeps_mixed_upstreams_nonfatal(
    tmp_path: Path,
) -> None:
    root = make_ca()
    anchor = tmp_path / "root.crt"
    anchor.write_bytes(root)
    store = tmp_path / "certs"
    store.mkdir()
    (store / "root.pem").write_bytes(root)

    def mixed_probe(
        hostname: str, upstream: str, root_pem: bytes, https_port: int
    ) -> dict[str, Any]:
        payload = healthy_route_probe(hostname, upstream, root_pem, https_port)
        if hostname.startswith("stopped."):
            payload["upstream_listening"] = False
            payload["warnings"] = [f"upstream is not listening: {upstream}"]
        return payload

    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=anchor,
        system_store_paths=(store,),
        route_probe=mixed_probe,
    )
    payload = inspector.status(
        registry(
            {
                "service": "stopped",
                "hostname": "stopped.example.localhost",
                "upstream": "http://127.0.0.1:20002",
            },
            {
                "service": "api",
                "hostname": "api.example.localhost",
                "upstream": "http://127.0.0.1:20001",
            },
        )
    )

    assert payload["ok"] is True
    assert [route["hostname"] for route in payload["routes"]] == [
        "api.example.localhost",
        "stopped.example.localhost",
    ]
    assert [route["upstream_listening"] for route in payload["routes"]] == [True, False]
    assert any("not listening" in warning for warning in payload["warnings"])


def test_export_is_atomic_idempotent_and_requires_force(tmp_path: Path) -> None:
    root = make_ca("Active")
    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=tmp_path / "anchor.crt",
        system_store_paths=(tmp_path / "certs",),
        route_probe=healthy_route_probe,
    )
    state = registry(
        {
            "service": "studio",
            "hostname": "studio.example.localhost",
            "upstream": "http://127.0.0.1:29734",
        }
    )
    output = tmp_path / "yan-port-root.crt"

    created = inspector.export(state, output)
    unchanged = inspector.export(state, output)

    assert created["changed"] is True
    assert unchanged["changed"] is False
    assert output.read_bytes() == root
    assert output.stat().st_mode & 0o777 == 0o644

    different = make_ca("Different")
    output.write_bytes(different)
    with pytest.raises(TrustError, match="already contains different content"):
        inspector.export(state, output)
    replaced = inspector.export(state, output, force=True)
    assert replaced["changed"] is True
    assert replaced["replaced_sha256"] == certificate_sha256(load_certificate(different))
    assert output.read_bytes() == root


def test_export_refuses_symlink_and_empty_registry(tmp_path: Path) -> None:
    root = make_ca()
    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=tmp_path / "anchor.crt",
        system_store_paths=(tmp_path / "certs",),
        route_probe=healthy_route_probe,
    )
    target = tmp_path / "target.crt"
    target.write_bytes(root)
    link = tmp_path / "link.crt"
    link.symlink_to(target)

    with pytest.raises(TrustError, match="symbolic link"):
        inspector.export(
            registry(
                {
                    "service": "studio",
                    "hostname": "studio.example.localhost",
                    "upstream": "http://127.0.0.1:29734",
                }
            ),
            link,
        )
    with pytest.raises(TrustError, match="no HTTPS routes"):
        inspector.export(registry(), tmp_path / "unused.crt")


def test_export_does_not_accept_matching_certificate_with_appended_content(
    tmp_path: Path,
) -> None:
    root = make_ca("Active")
    inspector = TrustInspector(
        FakeCaddy(root),
        system_anchor_path=tmp_path / "anchor.crt",
        system_store_paths=(tmp_path / "certs",),
        route_probe=healthy_route_probe,
    )
    state = registry(
        {
            "service": "studio",
            "hostname": "studio.example.localhost",
            "upstream": "http://127.0.0.1:29734",
        }
    )
    private_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    appended_values = [b"unexpected trailing data\n", make_ca("Second"), private_key]
    output = tmp_path / "yan-port-root.crt"

    for appended in appended_values:
        output.write_bytes(root + appended)
        with pytest.raises(TrustError, match="different content"):
            inspector.export(state, output)
        replaced = inspector.export(state, output, force=True)
        assert replaced["changed"] is True
        assert output.read_bytes() == root
