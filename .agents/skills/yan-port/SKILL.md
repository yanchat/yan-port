---
name: yan-port
description: Manage YanPort local routes, ports, Git worktree contexts, and exclusive development-resource reservations. Use when starting, stopping, diagnosing, or cleaning a local development environment; resolving localhost route or port collisions; or working with multiple Local/Codex worktree runtimes on the same machine.
---

# YanPort

Use `yan-port` as the only route and port authority. Never edit its registry or
generated Caddy configuration directly.

## Workflow

1. Run `yan-port context inspect --json` before starting a local runtime.
2. Let the project command call `context ensure`, allocate or claim ports, start
   its own services, then register exact routes.
3. Run `yan-port status --json` when a route, port, or reservation conflicts.
4. Stop only the current context through the owning project's command.
5. From the primary Local checkout, inspect and explicitly retire abandoned
   worktree contexts. Never infer ownership from a hostname or PID alone.

## Safety

- Do not call Caddy, edit the generated Caddyfile, or bind ports 80/443 directly.
- Do not reuse another context's port, route, lease file, or reservation.
- Treat every named reservation as exclusive. If acquisition fails, report the
  named owner; never stop or replace the owning runtime.
- Do not release a port while a route still refers to it.
- Do not delete volumes or project data through YanPort. Use the owning
  project's reviewed purge command.
- In a worktree, never perform global cleanup or router service operations.

Read [references/operations.md](references/operations.md) for command contracts
and failure recovery when direct YanPort operations are necessary.
