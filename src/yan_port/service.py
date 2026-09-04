"""Ownership-safe YanPort operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .caddy import CaddyController, validate_domain, validate_hostname, validate_upstream
from .context import detect_context
from .errors import CaddyError, ConflictError, ContextError
from .registry import StateStore


def _now() -> int:
    return int(time.time())


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _owner_id(project: str, checkout_path: str) -> str:
    return hashlib.sha256(f"{project}\0{checkout_path}".encode()).hexdigest()[:20]


def _route_domain(domain: str, kind: str, context_id: str) -> str:
    if kind == "local":
        return domain
    return f"{domain.removesuffix('.localhost')}-{context_id}.localhost"


def _validate_name(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or not all(
        character.isalnum() or character == "-" for character in normalized
    ):
        raise ValueError(f"{label} must contain only lowercase letters, digits, and hyphens")
    return normalized


def _port_available(port: int) -> bool:
    sockets: list[socket.socket] = []
    try:
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            handle = socket.socket(family, socket.SOCK_STREAM)
            sockets.append(handle)
            handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            handle.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        for handle in sockets:
            handle.close()


class YanPortService:
    def __init__(self, store: StateStore, caddy: CaddyController) -> None:
        self.store = store
        self.caddy = caddy

    def inspect_context(self, cwd: Path | str | None = None) -> dict[str, str]:
        return detect_context(cwd).as_dict()

    def ensure_context(
        self, *, project: str, domain: str, cwd: Path | str | None = None
    ) -> dict[str, Any]:
        info = detect_context(cwd)
        normalized_project = _validate_name(project, label="Project names")
        normalized_domain = validate_domain(domain)
        owner_id = _owner_id(normalized_project, info.checkout_path)
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            existing = registry["contexts"].get(owner_id)
            if existing:
                if existing["domain"] != normalized_domain:
                    raise ContextError(
                        f"Context {info.context_id} already uses domain {existing['domain']}"
                    )
                self._authenticate(existing)
                expected_route_domain = _route_domain(normalized_domain, info.kind, info.context_id)
                if existing.get("route_domain") != expected_route_domain:
                    existing["route_domain"] = expected_route_domain
                    existing["updated_at"] = _now()
                    registry["generation"] += 1
                    self.store.write(registry)
                return existing
            token = secrets.token_urlsafe(32)
            timestamp = _now()
            record: dict[str, Any] = {
                "owner_id": owner_id,
                "project": normalized_project,
                "domain": normalized_domain,
                "route_domain": _route_domain(normalized_domain, info.kind, info.context_id),
                **info.as_dict(),
                "token_hash": _token_hash(token),
                "ports": {},
                "routes": {},
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            self.store.write(
                {"version": 1, "owner_id": owner_id, "token": token},
                path=self.store.lease_path(owner_id),
            )
            registry["contexts"][owner_id] = record
            registry["generation"] += 1
            self.store.write(registry)
            return record

    def _context_for_cwd(
        self, registry: dict[str, Any], cwd: Path | str | None = None
    ) -> dict[str, Any]:
        info = detect_context(cwd)
        matches = [
            context
            for context in registry["contexts"].values()
            if context["checkout_path"] == info.checkout_path
        ]
        if not matches:
            raise ContextError(
                "This checkout has no YanPort lease; run `yan-port context ensure` first"
            )
        if len(matches) > 1:
            projects = ", ".join(sorted(context["project"] for context in matches))
            raise ContextError(
                f"Checkout has multiple YanPort projects ({projects}); specify a project"
            )
        self._authenticate(matches[0])
        return matches[0]

    def _authenticate(self, context: dict[str, Any]) -> None:
        path = self.store.lease_path(context["owner_id"])
        try:
            lease = json.loads(path.read_text())
            token = lease["token"]
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise ContextError(
                f"Lease credentials are missing for {context['project']}:{context['context_id']}"
            ) from exc
        if not hmac.compare_digest(_token_hash(token), context["token_hash"]):
            raise ContextError(
                f"Lease credentials do not own {context['project']}:{context['context_id']}"
            )

    def _used_ports(self, registry: dict[str, Any]) -> set[int]:
        return {
            int(port["port"])
            for context in registry["contexts"].values()
            for port in context.get("ports", {}).values()
        }

    def allocate_port(
        self,
        service: str,
        *,
        cwd: Path | str | None = None,
        preferred: int | None = None,
        range_start: int = 20000,
        range_end: int = 39999,
    ) -> dict[str, Any]:
        if range_start < 1024 or range_end > 65535 or range_start > range_end:
            raise ValueError("Port range must be within 1024..65535 and start before it ends")
        normalized_service = _validate_name(service, label="Service names")
        if preferred is not None and not 1024 <= preferred <= 65535:
            raise ValueError("Preferred port must be within 1024..65535")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            if normalized_service in context["ports"]:
                return context["ports"][normalized_service]
            used = self._used_ports(registry)
            candidates: list[int] = []
            if preferred is not None:
                candidates.append(preferred)
            width = range_end - range_start + 1
            offset = (
                int(
                    hashlib.sha256(
                        f"{context['owner_id']}\0{normalized_service}".encode()
                    ).hexdigest()[:8],
                    16,
                )
                % width
            )
            candidates.extend(range_start + ((offset + index) % width) for index in range(width))
            selected = next(
                (port for port in candidates if port not in used and _port_available(port)), None
            )
            if selected is None:
                raise ConflictError(f"No available YanPort port in {range_start}..{range_end}")
            record = {"service": normalized_service, "port": selected, "created_at": _now()}
            context["ports"][normalized_service] = record
            context["updated_at"] = _now()
            registry["generation"] += 1
            self.store.write(registry)
            return record

    def claim_port(
        self, service: str, port: int, *, cwd: Path | str | None = None
    ) -> dict[str, Any]:
        normalized_service = _validate_name(service, label="Service names")
        if not 1024 <= port <= 65535:
            raise ValueError("Claimed port must be within 1024..65535")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            existing = context["ports"].get(normalized_service)
            if existing:
                if existing["port"] != port:
                    raise ConflictError(
                        f"Service {normalized_service} already owns port {existing['port']}"
                    )
                return existing
            if port in self._used_ports(registry):
                raise ConflictError(f"Port {port} is already leased by another YanPort service")
            if not _port_available(port):
                raise ConflictError(f"Port {port} is already in use outside YanPort")
            record = {"service": normalized_service, "port": port, "created_at": _now()}
            context["ports"][normalized_service] = record
            context["updated_at"] = _now()
            registry["generation"] += 1
            self.store.write(registry)
            return record

    def release_port(self, service: str, *, cwd: Path | str | None = None) -> bool:
        normalized_service = _validate_name(service, label="Service names")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            if normalized_service not in context["ports"]:
                return False
            for route in context["routes"].values():
                if route.get("port_service") == normalized_service:
                    raise ConflictError(
                        f"Port {normalized_service} still has route {route['hostname']}"
                    )
            del context["ports"][normalized_service]
            context["updated_at"] = _now()
            registry["generation"] += 1
            self.store.write(registry)
            return True

    def _required_hostname_suffix(self, context: dict[str, Any]) -> str:
        return str(
            context.get("route_domain")
            or _route_domain(context["domain"], context["kind"], context["context_id"])
        )

    def _recover_route_transaction(self, registry: dict[str, Any]) -> dict[str, Any]:
        if not self.store.journal_path.exists():
            return registry
        journal = json.loads(self.store.journal_path.read_text())
        candidate = journal["candidate"]
        if registry.get("generation") == candidate.get("generation"):
            self.store.remove_journal()
            return registry
        previous = journal["previous"]
        self.caddy.apply(self.caddy.render(previous))
        self.store.write(previous)
        self.store.remove_journal()
        return previous

    def _apply_route_registry(self, previous: dict[str, Any], candidate: dict[str, Any]) -> None:
        self.store.write(
            {"version": 1, "previous": previous, "candidate": candidate},
            path=self.store.journal_path,
        )
        try:
            self.caddy.apply(self.caddy.render(candidate))
            self.store.write(candidate)
            self.store.remove_journal()
        except CaddyError:
            # Validation and /load failures leave Caddy's prior config active.
            self.store.remove_journal()
            raise

    def apply_route(
        self,
        service: str,
        *,
        hostname: str,
        upstream: str,
        port_service: str | None = None,
        cwd: Path | str | None = None,
    ) -> dict[str, Any]:
        return self._set_route(
            service,
            hostname=hostname,
            upstream=upstream,
            port_service=port_service,
            cwd=cwd,
            activate=True,
        )

    def stage_route(
        self,
        service: str,
        *,
        hostname: str,
        upstream: str,
        port_service: str | None = None,
        cwd: Path | str | None = None,
    ) -> dict[str, Any]:
        """Validate and persist a route before the first native Caddy cutover."""
        if Path(self.caddy.admin_socket).exists():
            raise ConflictError(
                "Route staging is only allowed before native Caddy is live; use route apply"
            )
        return self._set_route(
            service,
            hostname=hostname,
            upstream=upstream,
            port_service=port_service,
            cwd=cwd,
            activate=False,
        )

    def _set_route(
        self,
        service: str,
        *,
        hostname: str,
        upstream: str,
        port_service: str | None,
        cwd: Path | str | None,
        activate: bool,
    ) -> dict[str, Any]:
        normalized_service = _validate_name(service, label="Service names")
        normalized_host = validate_hostname(hostname)
        normalized_upstream = validate_upstream(upstream)
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            if not activate and context.get("kind") != "local":
                raise ConflictError("Route staging requires the primary Local checkout")
            suffix = self._required_hostname_suffix(context)
            if normalized_host != suffix and not normalized_host.endswith(f".{suffix}"):
                raise ConflictError(f"Host {normalized_host} is outside context domain {suffix}")
            for candidate_context in registry["contexts"].values():
                for candidate_service, route in candidate_context["routes"].items():
                    if route["hostname"] == normalized_host and not (
                        candidate_context["owner_id"] == context["owner_id"]
                        and candidate_service == normalized_service
                    ):
                        raise ConflictError(
                            f"Host {normalized_host} is owned by "
                            f"{candidate_context['project']}:{candidate_context['context_id']}"
                        )
            normalized_port_service = (
                _validate_name(port_service, label="Port service names")
                if port_service is not None
                else None
            )
            if (
                normalized_port_service is not None
                and normalized_port_service not in context["ports"]
            ):
                raise ConflictError(
                    f"Route references unleased port service {normalized_port_service}"
                )
            if normalized_port_service is not None:
                leased_port = int(context["ports"][normalized_port_service]["port"])
                upstream_port = int(urlsplit(normalized_upstream).port or 0)
                if upstream_port != leased_port:
                    raise ConflictError(
                        f"Route upstream port {upstream_port} does not match "
                        f"{normalized_port_service} lease {leased_port}"
                    )
            existing = context["routes"].get(normalized_service)
            record = {
                "service": normalized_service,
                "hostname": normalized_host,
                "upstream": normalized_upstream,
                "port_service": normalized_port_service,
                "updated_at": _now(),
            }
            if existing and all(
                existing.get(key) == record[key]
                for key in ("service", "hostname", "upstream", "port_service")
            ):
                if activate:
                    # A route may have been persisted by the first-cutover staging
                    # command. Re-applying an identical record must still reconcile
                    # the live Caddy process with the authoritative registry.
                    self.caddy.apply(self.caddy.render(registry))
                return existing
            candidate = self.store.clone(registry)
            candidate_context = candidate["contexts"][context["owner_id"]]
            candidate_context["routes"][normalized_service] = record
            candidate_context["updated_at"] = _now()
            candidate["generation"] += 1
            if activate:
                self._apply_route_registry(registry, candidate)
            else:
                self.caddy.validate(self.caddy.render(candidate))
                self.store.write(candidate)
            return record

    def remove_route(self, service: str, *, cwd: Path | str | None = None) -> bool:
        normalized_service = _validate_name(service, label="Service names")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            if normalized_service not in context["routes"]:
                return False
            candidate = self.store.clone(registry)
            del candidate["contexts"][context["owner_id"]]["routes"][normalized_service]
            candidate["contexts"][context["owner_id"]]["updated_at"] = _now()
            candidate["generation"] += 1
            self._apply_route_registry(registry, candidate)
            return True

    def acquire_reservation(self, name: str, *, cwd: Path | str | None = None) -> dict[str, Any]:
        normalized_name = _validate_name(name, label="Reservation names")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            existing = registry["reservations"].get(normalized_name)
            if existing:
                if existing["owner_id"] == context["owner_id"]:
                    return existing
                owner = registry["contexts"].get(existing["owner_id"], {})
                raise ConflictError(
                    f"Reservation {normalized_name} is owned by "
                    f"{owner.get('project', 'unknown')}:{owner.get('context_id', 'unknown')} "
                    f"at {owner.get('checkout_path', 'unknown')}"
                )
            record = {
                "name": normalized_name,
                "owner_id": context["owner_id"],
                "acquired_at": _now(),
            }
            registry["reservations"][normalized_name] = record
            registry["generation"] += 1
            self.store.write(registry)
            return record

    def release_reservation(self, name: str, *, cwd: Path | str | None = None) -> bool:
        normalized_name = _validate_name(name, label="Reservation names")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            context = self._context_for_cwd(registry, cwd)
            existing = registry["reservations"].get(normalized_name)
            if not existing:
                return False
            if existing["owner_id"] != context["owner_id"]:
                owner = registry["contexts"].get(existing["owner_id"], {})
                raise ConflictError(
                    f"Reservation {normalized_name} belongs to "
                    f"{owner.get('project', 'unknown')}:{owner.get('context_id', 'unknown')}"
                )
            del registry["reservations"][normalized_name]
            registry["generation"] += 1
            self.store.write(registry)
            return True

    def release_context(
        self,
        *,
        target: Path | str | None = None,
        owner_id: str | None = None,
        cwd: Path | str | None = None,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        caller = detect_context(cwd)
        if owner_id is not None and target is not None:
            raise ContextError("Choose either --owner or --target, not both")
        if owner_id is not None and caller.kind != "local":
            raise ContextError("Only the primary Local checkout may release by owner ID")

        requested_path: str | None = None
        if owner_id is None:
            requested = Path(target or cwd or Path.cwd()).resolve()
            if requested.exists():
                requested_path = detect_context(requested).checkout_path
            else:
                requested_path = str(requested)

        releasing_self = requested_path == caller.checkout_path
        if not releasing_self:
            if caller.kind != "local":
                raise ContextError("Only the primary Local checkout may release another context")
            if not confirmed:
                raise ContextError("Releasing another context requires --yes")
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            if owner_id is not None:
                selected = registry["contexts"].get(owner_id)
                matches = [selected] if selected is not None else []
            else:
                matches = [
                    context
                    for context in registry["contexts"].values()
                    if context["checkout_path"] == requested_path
                ]
            if not matches:
                target_label = owner_id or requested_path
                raise ContextError(f"No YanPort context exists for {target_label}")
            if len(matches) > 1:
                raise ContextError(
                    "Target checkout has multiple project contexts; release them separately"
                )
            context = matches[0]
            # A context may release itself with its lease. The primary Local checkout
            # is the administrative authority for an explicitly confirmed stale or
            # foreign context and therefore authenticates itself, not the target.
            if releasing_self:
                self._authenticate(context)
            else:
                caller_matches = [
                    item
                    for item in registry["contexts"].values()
                    if item["checkout_path"] == caller.checkout_path
                ]
                if len(caller_matches) != 1:
                    raise ContextError(
                        "The primary Local checkout must have exactly one YanPort context"
                    )
                self._authenticate(caller_matches[0])
            busy = [
                record
                for record in context["ports"].values()
                if not _port_available(int(record["port"]))
            ]
            if busy:
                rendered = ", ".join(f"{record['service']}:{record['port']}" for record in busy)
                raise ConflictError(f"Context still has listening services: {rendered}")
            candidate = self.store.clone(registry)
            owner_id = context["owner_id"]
            released_reservations = sorted(
                name
                for name, record in candidate["reservations"].items()
                if record["owner_id"] == owner_id
            )
            for name in released_reservations:
                del candidate["reservations"][name]
            del candidate["contexts"][owner_id]
            candidate["generation"] += 1
            if context["routes"]:
                self._apply_route_registry(registry, candidate)
            else:
                self.store.write(candidate)
            self.store.lease_path(owner_id).unlink(missing_ok=True)
            return {
                "project": context["project"],
                "context_id": context["context_id"],
                "routes": sorted(context["routes"]),
                "ports": sorted(context["ports"]),
                "reservations": released_reservations,
            }

    def status(self) -> dict[str, Any]:
        with self.store.lock():
            registry = self._recover_route_transaction(self.store.load())
            return self.store.clone(registry)

    def doctor(self) -> dict[str, Any]:
        with self.store.lock():
            registry = self.store.load()
            hosts: dict[str, str] = {}
            problems: list[str] = []
            for context in registry["contexts"].values():
                if not Path(context["checkout_path"]).exists():
                    problems.append(
                        f"stale context path: {context['project']}:{context['context_id']}"
                    )
                for route in context["routes"].values():
                    previous = hosts.get(route["hostname"])
                    if previous:
                        problems.append(f"duplicate host: {route['hostname']} ({previous})")
                    hosts[route["hostname"]] = context["owner_id"]
            return {
                "ok": not problems and not self.store.journal_path.exists(),
                "generation": registry["generation"],
                "contexts": len(registry["contexts"]),
                "routes": len(hosts),
                "reservations": len(registry["reservations"]),
                "pending_route_transaction": self.store.journal_path.exists(),
                "problems": problems,
            }
