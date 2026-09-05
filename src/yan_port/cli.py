"""YanPort Typer command line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from .caddy import CaddyController, render_caddyfile
from .errors import YanPortError
from .registry import StateStore
from .service import YanPortService

app = typer.Typer(help="Ownership-safe local routing and worktree isolation.", no_args_is_help=True)
context_app = typer.Typer(help="Inspect and establish checkout identity.", no_args_is_help=True)
port_app = typer.Typer(help="Allocate ownership-safe local ports.", no_args_is_help=True)
route_app = typer.Typer(help="Manage exact local HTTPS routes.", no_args_is_help=True)
reservation_app = typer.Typer(
    help="Manage exclusive machine-wide reservations.", no_args_is_help=True
)
router_app = typer.Typer(help="Inspect and update the Caddy front door.", no_args_is_help=True)
trust_app = typer.Typer(help="Inspect and export local certificate trust.", no_args_is_help=True)
app.add_typer(context_app, name="context")
app.add_typer(port_app, name="port")
app.add_typer(route_app, name="route")
app.add_typer(reservation_app, name="reservation")
app.add_typer(router_app, name="router")
app.add_typer(trust_app, name="trust")


def _service() -> YanPortService:
    store = StateStore()
    return YanPortService(store, CaddyController())


def _emit(payload: Any, *, as_json: bool = False, plain_key: str | None = None) -> None:
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    elif plain_key is not None and isinstance(payload, dict):
        typer.echo(payload[plain_key])
    elif isinstance(payload, bool):
        typer.echo("ok" if payload else "not found")
    else:
        typer.echo(payload)


def _run(operation: Any) -> Any:
    try:
        return operation()
    except (YanPortError, ValueError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc


def _format_fingerprint(fingerprint: str | None) -> str:
    if fingerprint is None:
        return "unavailable"
    rendered = fingerprint.upper()
    return ":".join(rendered[index : index + 2] for index in range(0, len(rendered), 2))


def _emit_trust_status(payload: dict[str, Any]) -> None:
    typer.echo(f"Trust state: {payload['state']}")
    root = payload["root_ca"]
    typer.echo(f"Active root CA path: {root['path']}")
    typer.echo(f"Active root SHA-256: {_format_fingerprint(root['sha256'])}")
    system = payload["system_trust"]
    typer.echo(f"System CA anchor: {system['anchor_path']}")
    typer.echo(f"System anchor SHA-256: {_format_fingerprint(system['anchor_sha256'])}")
    typer.echo(f"Installed in system trust store: {'yes' if system['installed'] else 'no'}")
    typer.echo(f"System anchor matches active root: {'yes' if system['matches_active'] else 'no'}")
    if payload["routes"]:
        typer.echo("Routes:")
    for route in payload["routes"]:
        typer.echo(f"  {route['hostname']}")
        typer.echo(f"    Leaf SHA-256: {_format_fingerprint(route['leaf_sha256'])}")
        typer.echo(f"    TLS reachable: {'yes' if route['tls_reachable'] else 'no'}")
        typer.echo(
            f"    Chains to active root: {'yes' if route['chains_to_active_root'] else 'no'}"
        )
        typer.echo(f"    Hostname appears in SAN: {'yes' if route['san_matches'] else 'no'}")
        typer.echo(f"    System TLS trust: {'yes' if route['system_trusted'] else 'no'}")
        typer.echo(
            f"    Upstream listening: {'yes' if route['upstream_listening'] else 'no'} "
            f"({route['upstream']})"
        )
    if payload["warnings"]:
        typer.echo("Warnings:")
        for warning in payload["warnings"]:
            typer.echo(f"  - {warning}")
    if payload["problems"]:
        typer.echo("Problems:")
        for problem in payload["problems"]:
            typer.echo(f"  - {problem}")


@context_app.command("inspect")
def context_inspect(
    cwd: Annotated[Path | None, typer.Option(help="Checkout path to inspect.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().inspect_context(cwd))
    _emit(payload, as_json=json_output, plain_key="context_id")


@context_app.command("ensure")
def context_ensure(
    project: Annotated[str, typer.Option(help="Stable project identifier.")],
    domain: Annotated[str, typer.Option(help="Project base .localhost domain.")],
    cwd: Annotated[Path | None, typer.Option(help="Checkout path to register.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().ensure_context(project=project, domain=domain, cwd=cwd))
    _emit(payload, as_json=json_output, plain_key="context_id")


@context_app.command("release")
def context_release(
    target: Annotated[
        Path | None, typer.Option(help="Checkout to release; defaults to the current checkout.")
    ] = None,
    owner: Annotated[
        str | None,
        typer.Option(
            help="Registry owner ID to release after its checkout was deleted (Local only)."
        ),
    ] = None,
    cwd: Annotated[Path | None, typer.Option(help="Calling checkout path.")] = None,
    yes: Annotated[
        bool, typer.Option("--yes", help="Confirm releasing a different checkout.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(
        lambda: _service().release_context(target=target, owner_id=owner, cwd=cwd, confirmed=yes)
    )
    _emit(payload, as_json=json_output)


@port_app.command("allocate")
def port_allocate(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    preferred: Annotated[int | None, typer.Option(help="Preferred port when available.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().allocate_port(service, cwd=cwd, preferred=preferred))
    _emit(payload, as_json=json_output, plain_key="port")


@port_app.command("claim")
def port_claim(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    port: Annotated[int, typer.Argument(help="Already assigned loopback port.")],
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().claim_port(service, port, cwd=cwd))
    _emit(payload, as_json=json_output, plain_key="port")


@port_app.command("release")
def port_release(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
) -> None:
    _emit(_run(lambda: _service().release_port(service, cwd=cwd)))


@route_app.command("apply")
def route_apply(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    hostname: Annotated[str, typer.Option("--host", help="Exact .localhost hostname.")],
    upstream: Annotated[str, typer.Option(help="Loopback HTTP origin.")],
    port_service: Annotated[
        str | None, typer.Option(help="Optional leased port service backing this route.")
    ] = None,
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(
        lambda: _service().apply_route(
            service,
            hostname=hostname,
            upstream=upstream,
            port_service=port_service,
            cwd=cwd,
        )
    )
    _emit(payload, as_json=json_output, plain_key="hostname")


@route_app.command("stage")
def route_stage(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    hostname: Annotated[str, typer.Option("--host", help="Exact .localhost hostname.")],
    upstream: Annotated[str, typer.Option(help="Loopback HTTP origin.")],
    port_service: Annotated[
        str | None, typer.Option(help="Optional leased port service backing this route.")
    ] = None,
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Preload a validated route before the first native Caddy activation."""
    payload = _run(
        lambda: _service().stage_route(
            service,
            hostname=hostname,
            upstream=upstream,
            port_service=port_service,
            cwd=cwd,
        )
    )
    _emit(payload, as_json=json_output, plain_key="hostname")


@route_app.command("remove")
def route_remove(
    service: Annotated[str, typer.Argument(help="Context-local service name.")],
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
) -> None:
    _emit(_run(lambda: _service().remove_route(service, cwd=cwd)))


@reservation_app.command("acquire")
def reservation_acquire(
    name: Annotated[str, typer.Argument(help="Exclusive machine-wide resource name.")],
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().acquire_reservation(name, cwd=cwd))
    _emit(payload, as_json=json_output, plain_key="name")


@reservation_app.command("release")
def reservation_release(
    name: Annotated[str, typer.Argument(help="Exclusive machine-wide resource name.")],
    cwd: Annotated[Path | None, typer.Option(help="Registered checkout path.")] = None,
) -> None:
    _emit(_run(lambda: _service().release_reservation(name, cwd=cwd)))


@reservation_app.command("show")
def reservation_show(
    name: Annotated[str, typer.Argument(help="Exclusive machine-wide resource name.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().status()["reservations"].get(name))
    if payload is None:
        raise typer.Exit(1)
    _emit(payload, as_json=json_output)


@app.command("status")
def status(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    _emit(_run(lambda: _service().status()), as_json=json_output)


@app.command("doctor")
def doctor(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().doctor())
    _emit(payload, as_json=json_output)
    if not payload["ok"]:
        raise typer.Exit(1)


@trust_app.command("status")
def trust_status(
    hostname: Annotated[
        str | None, typer.Option("--host", help="Exact registered .localhost route to inspect.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().trust_status(hostname))
    if json_output:
        _emit(payload, as_json=True)
    else:
        _emit_trust_status(payload)
    if not payload["ok"]:
        raise typer.Exit(1)


@trust_app.command("export")
def trust_export(
    output: Annotated[Path, typer.Option(help="Destination for the active public root CA.")],
    force: Annotated[
        bool, typer.Option("--force", help="Atomically replace a differing regular file.")
    ] = False,
) -> None:
    payload = _run(lambda: _service().trust_export(output, force=force))
    action = "Exported" if payload["changed"] else "Already current"
    typer.echo(f"{action}: {payload['output']}")
    typer.echo(f"SHA-256: {_format_fingerprint(payload['sha256'])}")
    if payload["changed"] and payload["replaced_sha256"]:
        if payload["replaced_sha256"] == payload["sha256"]:
            typer.echo("Replaced matching certificate with canonical root-only PEM.")
        else:
            typer.echo(f"Replaced SHA-256: {_format_fingerprint(payload['replaced_sha256'])}")


@router_app.command("render")
def router_render(
    http_port: Annotated[int, typer.Option(help="HTTP listener port.")] = 80,
    https_port: Annotated[int, typer.Option(help="HTTPS listener port.")] = 443,
    admin_socket: Annotated[
        str | None, typer.Option(help="Admin Unix socket path override.")
    ] = None,
) -> None:
    service = _service()
    typer.echo(
        render_caddyfile(
            service.status(),
            admin_socket=admin_socket or service.caddy.admin_socket,
            http_port=http_port,
            https_port=https_port,
        ),
        nl=False,
    )


@router_app.command("validate")
def router_validate() -> None:
    service = _service()
    content = service.caddy.render(service.status())
    _run(lambda: service.caddy.validate(content))
    typer.echo("valid")


@router_app.command("reload")
def router_reload() -> None:
    service = _service()
    content = service.caddy.render(service.status())
    _run(lambda: service.caddy.apply(content))
    typer.echo("reloaded")


@router_app.command("status")
def router_status(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    payload = {
        "service": "yan-port-caddy.service",
        "state": _run(lambda: _service().caddy.status()),
    }
    _emit(payload, as_json=json_output)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
