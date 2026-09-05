# YanPort

YanPort is an ownership-safe routing layer for local development projects.
It gives the primary checkout and each Git worktree isolated route, port, and
exclusive-resource leases while one native Caddy process owns ports 80 and 443.

YanPort is intentionally local-only. It accepts exact `.localhost` hostnames,
proxies only to loopback HTTP upstreams, and redirects HTTP to HTTPS only for
registered exact hostnames.

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check .
uv run yan-port --help
```

## Basic integration

```bash
yan-port context ensure --project example-app --domain example.localhost
port="$(yan-port port allocate api)"
yan-port route apply api \
  --host api.example.localhost \
  --upstream "http://127.0.0.1:${port}" \
  --port-service api
yan-port trust status --host api.example.localhost
yan-port status --json
```

Project tooling should call YanPort; agents and projects must not edit the
generated Caddy configuration or registry directly.

YanPort installs Caddy's local CA into the Linux system trust store during the
first native-Caddy cutover. Some Chromium and Electron applications use trust
state that differs from command-line system clients. Use `yan-port trust status`
to separate routing, certificate, system-trust, embedded-browser, and upstream
problems. Use `yan-port trust export --output ./yan-port-root.crt` for an
explicit manual import; YanPort never discovers or modifies browser profiles.

See [Local certificate trust](docs/trust.md) for Chrome, Chromium, Electron,
Codex, containers, CI, and direct-HTTP guidance. Application launchers should
follow the [application CLI lifecycle](docs/application-lifecycle.md) while
remaining responsible for their own processes.

The packaged wheel supplies the `yan-port` CLI. Native Caddy installation and
first-machine cutover use the repository's `deploy/`, `scripts/`, and `justfile`
assets, so those system-level operations must be run from a source checkout.

## Native Caddy

YanPort pins the reviewed official Caddy 2.11.4 Linux amd64 release by SHA-512.
Installation is deliberately split from activation so the existing front door
is never replaced as a side effect:

```bash
just install-caddy
just install-service
```

Those commands install `/usr/local/bin/caddy` and the dormant
`yan-port-caddy.service`. Starting the service and handing over ports 80/443 is
a separate, probe-guarded cutover operation.

For a first migration, preload every existing route with `yan-port route stage`
while the legacy front door is still active. Staging validates the complete
candidate but deliberately does not contact a Caddy admin socket. It is not a
normal application operation; after activation, applications use `route apply`
so the registry and live proxy change atomically.

```bash
yan-port route stage web \
  --host app.example.localhost \
  --upstream http://127.0.0.1:5173 \
  --cwd /path/to/example-app
yan-port router render > /tmp/yan-port.Caddyfile
sudo install -o caddy -g yan-port -m 0640 \
  /tmp/yan-port.Caddyfile /var/lib/yan-port/Caddyfile
sudo scripts/cutover-native-caddy.sh --yes \
  --legacy-container existing-caddy \
  --probe https://app.example.localhost/
```

The cutover starts the same configuration on temporary high ports, installs its
local CA, continuously probes through the handoff, and enables the native
service for boot persistence. It restores the named legacy Docker listener and
disables the native service automatically if activation fails. Under `sudo`, it
recovers the invoking user's Docker Desktop or rootless Unix socket when
`DOCKER_HOST` was removed, so it hands off the listener visible in that user's
normal shell rather than an unrelated root daemon.

## License

YanPort is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
