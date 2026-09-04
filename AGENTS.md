# YanPort Agent Guide

YanPort is the single machine-wide local routing authority for development projects.
It owns context identity, route and port leases, Caddy configuration, and
exclusive resource reservations. Product repositories own their processes,
Compose stacks, databases, and application-specific teardown.

## Invariants

- Treat the primary Git checkout and every linked worktree as separate contexts.
- Derive worktree identity from Git/path metadata, never a branch name.
- Serialize registry changes and replace the complete Caddy configuration in one request.
- Require the matching lease for every mutation. Never remove by hostname prefix.
- Accept only exact `.localhost` hosts and loopback HTTP upstreams.
- Never steal a route, port, context, or named reservation.
- Cleanup is explicit. Report stale state; do not garbage-collect it automatically.
- Keep Caddy and its admin socket loopback/local-only.
- Add or update fail-first tests for every behavioral change.

Use the `yan-port` skill for operational work. Keep `just` recipes as thin
aliases over the packaged Typer CLI.
