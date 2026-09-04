from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cutover_enables_service_and_rolls_enablement_back_on_failure() -> None:
    script = (ROOT / "scripts" / "cutover-native-caddy.sh").read_text()

    enable = script.index("systemctl enable yan-port-caddy.service")
    start = script.index("systemctl start yan-port-caddy.service", enable)
    verify_active = script.index("systemctl is-active --quiet yan-port-caddy.service", start)
    verify_enabled = script.index("systemctl is-enabled --quiet yan-port-caddy.service", start)
    nft_table = script.index("nft add table inet yan_port_cutover")
    nft_chain = script.index("nft 'add chain inet yan_port_cutover", nft_table)

    assert enable < start < verify_active < verify_enabled
    assert nft_table < nft_chain
    assert "if systemctl is-active --quiet yan-port-caddy.service" in script
    assert "if systemctl is-enabled --quiet yan-port-caddy.service" in script
    assert "if nft list table inet yan_port_cutover" in script
    assert "docker inspect --format '{{.State.Running}}'" in script


def test_cutover_selects_owning_docker_daemon_before_inspection() -> None:
    script = (ROOT / "scripts" / "cutover-native-caddy.sh").read_text()

    selection = script.index('select-docker-endpoint.sh" "${legacy_container}"')
    inspect_legacy = script.index('docker inspect "${legacy_container}"')

    assert selection < inspect_legacy


def test_cutover_requires_an_explicit_legacy_container() -> None:
    script = (ROOT / "scripts" / "cutover-native-caddy.sh").read_text()

    assert 'legacy_container=""' in script
    assert "Cutover requires --legacy-container NAME." in script


def _fake_docker_environment(tmp_path: Path, matching_hosts: str) -> dict[str, str]:
    executable = tmp_path / "bin" / "docker"
    executable.parent.mkdir()
    executable.write_text(
        "#!/usr/bin/env bash\n"
        "host=${DOCKER_HOST:-default}\n"
        '[[ ",${MATCHING_HOSTS}," == *",${host},"* ]]\n'
    )
    executable.chmod(0o755)
    environment = os.environ.copy()
    environment.pop("DOCKER_HOST", None)
    environment["PATH"] = f"{executable.parent}:{environment['PATH']}"
    environment["MATCHING_HOSTS"] = matching_hosts
    return environment


def test_docker_endpoint_selection_probes_each_candidate(tmp_path: Path) -> None:
    first = tmp_path / "desktop.sock"
    second = tmp_path / "rootless.sock"
    with socket.socket(socket.AF_UNIX) as first_socket, socket.socket(
        socket.AF_UNIX
    ) as second_socket:
        first_socket.bind(str(first))
        second_socket.bind(str(second))
        expected = f"unix://{second}"
        result = subprocess.run(
            [
                str(ROOT / "scripts" / "select-docker-endpoint.sh"),
                "legacy",
                "",
                str(first),
                str(second),
            ],
            env=_fake_docker_environment(tmp_path, expected),
            capture_output=True,
            text=True,
            check=True,
        )

    assert result.stdout.strip() == expected


def test_docker_endpoint_selection_refuses_ambiguous_daemons(tmp_path: Path) -> None:
    first = tmp_path / "desktop.sock"
    second = tmp_path / "rootless.sock"
    with socket.socket(socket.AF_UNIX) as first_socket, socket.socket(
        socket.AF_UNIX
    ) as second_socket:
        first_socket.bind(str(first))
        second_socket.bind(str(second))
        matches = f"unix://{first},unix://{second}"
        result = subprocess.run(
            [
                str(ROOT / "scripts" / "select-docker-endpoint.sh"),
                "legacy",
                "",
                str(first),
                str(second),
            ],
            env=_fake_docker_environment(tmp_path, matches),
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode == 1
    assert "Multiple Docker endpoints" in result.stderr
