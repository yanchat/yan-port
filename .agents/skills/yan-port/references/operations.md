# YanPort Operations

## Contexts

`yan-port context inspect --json` reports `main` for the primary checkout and a
stable `wt-*` identity for linked worktrees. Register once with:

```bash
yan-port context ensure --project example-app --domain example.localhost --json
```

The owner token is stored outside the repository. Do not copy it between
worktrees.

## Ports and routes

Allocate host-process ports before launch. Claim Docker-assigned ports only
after reading them from `docker compose port`.

```bash
port="$(yan-port port allocate api)"
yan-port route apply api \
  --host "api.example.localhost" \
  --upstream "http://127.0.0.1:${port}" \
  --port-service api
```

The primary checkout uses the base domain. A linked worktree receives a stable
`*-wt-*.localhost` route domain; read its exact value from
`yan-port context ensure --json` instead of constructing or borrowing one.

Remove the route before releasing its port. Configuration replacement is
serialized and atomic; a rejected candidate leaves the previous routes live.

## Exclusive resources

Acquire any machine-exclusive resource before starting the runtime that uses it:

```bash
yan-port reservation acquire shared-model --json
```

Contention fails immediately with the current owner. Release only after the
owning runtime is stopped.

## Recovery

- Use `yan-port doctor --json` to find stale paths or a pending transaction.
- Use the owning project command to stop processes and containers first.
- Release the current context with `yan-port context release`.
- From primary Local, release another stopped context with
  `yan-port context release --target /absolute/worktree/path --yes`.
- If Git already removed the directory, copy its owner ID from `yan-port status
  --json` and use `yan-port context release --owner OWNER_ID --yes` from Local.
- Never delete YanPort state files to resolve a conflict.
