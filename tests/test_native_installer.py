from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("active,enabled", [(False, False), (True, False), (False, True)])
@pytest.mark.parametrize("failure", ["", "health", "enable", "start", "config"])
def test_fresh_activation_restores_prior_service_state(tmp_path, active, enabled, failure):
    scripts = tmp_path / "scripts"
    deploy = tmp_path / "deploy"
    scripts.mkdir()
    shutil.copytree(ROOT / "deploy", deploy)
    (scripts / "install-service.sh").write_text("exit 0\n")
    unit = tmp_path / "installed.service"
    config = tmp_path / "Caddyfile"
    shutil.copy(deploy / "yan-port-caddy.service", unit)
    shutil.copy(deploy / "bootstrap.Caddyfile", config)
    if failure == "config":
        config.write_text("existing custom routes")
    config_before = config.read_bytes()
    body = (ROOT / "scripts/activate-service.sh").read_text()
    # Simulate lifecycle calls without root; privilege admission is tested at the CLI.
    body = body.replace(
        '[[ "$EUID" -eq 0 ]] || { echo "Native activation requires sudo authentication" '
        ">&2; exit 1; }",
        ":",
    )
    body = body.replace("/etc/systemd/system/yan-port-caddy.service", str(unit))
    body = body.replace("/var/lib/yan-port/Caddyfile", str(config))
    script = scripts / "activate-service.sh"
    script.write_text(body)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"active": active, "enabled": enabled}))
    binary = tmp_path / "bin"
    binary.mkdir()
    systemctl = binary / "systemctl"
    systemctl.write_text(f"""#!{sys.executable}
import json, os, sys
from pathlib import Path
path = Path(os.environ["TEST_STATE"])
state = json.loads(path.read_text())
command = sys.argv[1]
if command in ("is-active", "is-enabled"):
    key = "active" if command == "is-active" else "enabled"
    if "--quiet" not in sys.argv:
        print(key if state[key] else ("inactive" if key == "active" else "disabled"))
    sys.exit(0 if state[key] else 1)
if command in ("start", "stop"): state["active"] = command == "start"
elif command in ("enable", "disable"): state["enabled"] = command == "enable"
else: sys.exit(99)
path.write_text(json.dumps(state))
sys.exit(1 if command == os.environ["TEST_FAILURE"] else 0)
""")
    systemctl.chmod(0o755)
    curl = binary / "curl"
    curl.write_text('#!/bin/sh\n[ "$TEST_FAILURE" != health ] || exit 1\necho "YanPort ready"\n')
    curl.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", str(script), "--yes"],
        env={
            **os.environ,
            "PATH": f"{binary}:/usr/bin:/bin",
            "TEST_STATE": str(state),
            "TEST_FAILURE": failure,
        },
        capture_output=True,
        text=True,
    )
    failed = (
        failure in {"health", "config"}
        or (failure == "enable" and not enabled)
        or (failure == "start" and not active)
    )
    assert result.returncode == (1 if failed else 0), result.stderr
    assert json.loads(state.read_text()) == (
        {"active": active, "enabled": enabled} if failed else {"active": True, "enabled": True}
    )
    assert config.read_bytes() == config_before


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "unit",
        "unit-link",
        "unit-directory",
        "override",
        "competing",
        "state-link",
        "config-link",
        "config-directory",
    ],
)
def test_service_preflight_preserves_existing_files(tmp_path: Path, defect: str | None) -> None:
    units = tmp_path / "units"
    units.mkdir()
    state = tmp_path / "state"
    source = ROOT / "scripts/install-service.sh"
    script = source.read_text()
    # Exercise the read-only preflight without root or the account/service phase.
    preflight = script[script.index("for unit in ") : script.index("if account=")]
    preflight = preflight.replace("/etc/systemd/system", str(units))
    for name, directory in (
        ("runtime", "/run/systemd/system"),
        ("vendor", "/usr/lib/systemd/system"),
        ("legacy", "/lib/systemd/system"),
    ):
        preflight = preflight.replace(directory, str(tmp_path / name))
    preflight = preflight.replace("/var/lib/yan-port", str(state))
    first = units / "yan-port-caddy.service"
    if defect == "unit-link":
        first.symlink_to(tmp_path / "missing-unit")
    elif defect == "unit-directory":
        first.mkdir()
    else:
        shutil.copy(ROOT / "deploy/yan-port-caddy.service", first)
        if defect == "unit":
            first.write_text("foreign unit")
    if defect == "override":
        (units / "yan-port-caddy.service.d").mkdir()
    if defect == "competing":
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "yan-port-caddy.service").write_text("foreign vendor unit")
    if defect == "state-link":
        state.symlink_to(tmp_path / "missing-state")
    else:
        state.mkdir()
        config = state / "Caddyfile"
        if defect == "config-link":
            config.symlink_to(tmp_path / "missing-config")
        elif defect == "config-directory":
            config.mkdir()
        else:
            config.write_text("preserve custom routes")
    original = first.lstat()
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + preflight],
        env={**os.environ, "repo_dir": str(ROOT)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == (1 if defect else 0), result.stderr
    assert first.lstat().st_ino == original.st_ino
    if defect == "unit":
        assert first.read_text() == "foreign unit"
    if defect is None:
        assert (state / "Caddyfile").read_text() == "preserve custom routes"
    assert not (units / "yan-port-caddy-cutover.service").exists()


@pytest.mark.parametrize(
    "account,groups,lookup_status,accepted",
    [
        ("", "", 2, True),
        ("", "", 1, False),
        ("caddy:x:998:998::/var/lib/yan-port:/usr/sbin/nologin", "caddy yan-port", 0, True),
        ("caddy:x:0:998::/var/lib/yan-port:/usr/sbin/nologin", "caddy", 0, False),
        ("caddy:x:998:0::/var/lib/yan-port:/usr/sbin/nologin", "caddy", 0, False),
        ("caddy:x:998:998::/var/lib/caddy:/usr/sbin/nologin", "caddy", 0, False),
        ("caddy:x:998:998::/var/lib/yan-port:/bin/bash", "caddy", 0, False),
        ("caddy:x:998:998::/var/lib/yan-port:/usr/sbin/nologin", "caddy sudo", 0, False),
        ("caddy:x:998:998::/var/lib/yan-port:/usr/sbin/nologin", "caddy docker", 0, False),
    ],
)
def test_service_account_preflight(tmp_path, account, groups, lookup_status, accepted):
    script = (ROOT / "scripts/install-service.sh").read_text()
    preflight = script[script.index("if account=") : script.index("if group_entry=")]
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, body in {
        "getent": 'printf "%s\\n" "$ACCOUNT"; exit "$LOOKUP_STATUS"',
        "id": 'printf "%s\\n" "$ACCOUNT_GROUPS"',
    }.items():
        tool = binary / name
        tool.write_text(f"#!/bin/sh\n{body}\n")
        tool.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + preflight],
        env={
            **os.environ,
            "PATH": str(binary),
            "ACCOUNT": account,
            "ACCOUNT_GROUPS": groups,
            "LOOKUP_STATUS": str(lookup_status),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == (0 if accepted else 1), result.stderr
    if not accepted:
        assert "caddy account" in result.stderr


@pytest.mark.parametrize(
    "group_status,group_entry,owner,accepted",
    [
        (0, "yan-port:x:999:", "998:999", True),
        (0, "yan-port:x:999:", "1000:999", False),
        (0, "yan-port:x:999:", "998:1000", False),
        (0, "yan-port:x:0:", "998:0", False),
        (2, "", "998:999", False),
        (1, "", "998:999", False),
    ],
)
def test_state_ownership_preflight(tmp_path, group_status, group_entry, owner, accepted):
    state = tmp_path / "state"
    state.mkdir()
    config = state / "Caddyfile"
    config.write_text("keep")
    script = (ROOT / "scripts/install-service.sh").read_text()
    preflight = script[
        script.index("if group_entry=") : script.index('[[ -n "$state_gid" ]] || groupadd')
    ]
    preflight = preflight.replace("/var/lib/yan-port", str(state))
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, body in {
        "getent": 'printf "%s\\n" "$GROUP_ENTRY"; exit "$GROUP_STATUS"',
        "stat": 'printf "%s\\n" "$STATE_OWNER"',
    }.items():
        tool = binary / name
        tool.write_text(f"#!/bin/sh\n{body}\n")
        tool.chmod(0o755)
    before = config.stat()
    result = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + preflight],
        env={
            **os.environ,
            "PATH": str(binary),
            "uid": "998",
            "GROUP_ENTRY": group_entry,
            "GROUP_STATUS": str(group_status),
            "STATE_OWNER": owner,
            "check_only": "false",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == (0 if accepted else 1), result.stderr
    assert config.read_text() == "keep"
    assert config.stat().st_ino == before.st_ino
    assert config.stat().st_mode == before.st_mode


@pytest.mark.parametrize(
    "existing", ["matching", "different", "nonexecutable", "symlink", "directory"]
)
def test_binary_installer_preserves_existing_destination(tmp_path: Path, existing: str) -> None:
    binary = tmp_path / "bin"
    binary.mkdir()
    target = tmp_path / "install with spaces"
    target.mkdir()
    candidate = tmp_path / "verified-caddy"
    candidate.write_text("#!/bin/sh\necho v2.11.4\n")
    candidate.chmod(0o755)
    destination = target / "caddy"
    if existing == "directory":
        destination.mkdir()
    elif existing == "symlink":
        destination.symlink_to(candidate)
    else:
        destination.write_bytes(candidate.read_bytes() if existing != "different" else b"preserve")
        destination.chmod(0o600 if existing == "nonexecutable" else 0o755)
    before = destination.lstat()
    stubs = {
        "uname": 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac',
        "curl": "exit 0",
        "sha512sum": "cat >/dev/null; exit 0",
        "tar": (
            'while [ "$#" -gt 0 ]; do if [ "$1" = --directory ]; then shift; '
            'cp "$CANDIDATE" "$1/caddy"; exit; fi; shift; done; exit 9'
        ),
        "install": 'echo "unexpected installation" >&2; exit 99',
    }
    for name, body in stubs.items():
        tool = binary / name
        tool.write_text(f"#!/bin/sh\n{body}\n")
        tool.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/install-caddy-binary.sh"), "--install-dir", str(target)],
        env={**os.environ, "PATH": f"{binary}:/usr/bin:/bin", "CANDIDATE": str(candidate)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (0 if existing == "matching" else 1), result.stderr
    assert "unexpected installation" not in result.stderr
    assert destination.lstat().st_ino == before.st_ino
    assert destination.lstat().st_mode == before.st_mode
    if existing == "matching":
        assert "Reusing verified Caddy" in result.stdout
    elif existing in {"different", "nonexecutable"}:
        assert "differs from the verified pin" in result.stderr
    else:
        assert "explicit repair" in result.stderr
    assert candidate.read_text() == "#!/bin/sh\necho v2.11.4\n"
    if existing == "different":
        assert destination.read_bytes() == b"preserve"
