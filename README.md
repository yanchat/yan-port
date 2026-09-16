# YanPort

YanPort is an ownership-safe routing layer for local development projects.
It gives the primary checkout and each Git worktree isolated route, port, and
exclusive-resource leases while one Caddy router owns ports 80 and 443. Linux
uses the native service; macOS uses an ownership-labeled Docker container.

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

The packaged wheel supplies the `yan-port` CLI and the existing native scripts
and deployment templates under `yan_port/native/`. The build includes these
directly from `scripts/` and `deploy/`, preserving their relative paths without
maintaining a second copy. `yan-port router provision-native --yes` uses those
assets (or the same source files in an editable checkout), checks prerequisites
and service conflicts, and requests sudo only for the existing installers.
Live Linux provisioning acceptance remains outstanding.

## Native Caddy

YanPort pins the reviewed official Caddy 2.11.4 Linux amd64 release by SHA-512.
Installation is deliberately split from activation so the existing front door
is never replaced as a side effect:

```bash
yan-port router provision-native --yes
```

The binary installer reuses an executable only when its bytes match the
checksum-verified pinned archive. This comparison still downloads the archive.
It refuses different binaries, non-executable files, directories and symlinks;
resolve conflicts explicitly rather than replacing another installation.

Service installation preserves matching unit files and regular router
configuration. Differing units, linked/non-regular unit destinations, or
linked/non-regular state paths require explicit repair before account changes.
This is not an in-place service upgrade procedure; inspect systemd overrides
and account ownership before accepting an existing native installation.
The installer rejects per-unit override directories and competing runtime/vendor
units. An existing `caddy` account must use YanPort's service home, a nologin
shell, non-root IDs and no root/sudo/wheel/docker group membership. Lookup
failures stop provisioning rather than being treated as a missing account.
Existing state directories and Caddyfiles must match that account and the
non-root `yan-port` group. Unverified ownership is refused, not corrected with
`chown`; existing state-directory permissions are preserved.

Provisioning installs `/usr/local/bin/caddy` and the dormant native service.
After re-login, a fresh installation with the unchanged bootstrap can be
activated explicitly:

```bash
yan-port router activate-native --yes
```

This checks the loopback bootstrap endpoint on port 2018 before enabling boot
startup. Failure restores prior running/enabled state without deleting data.
Existing custom route configurations are refused. This is not HTTPS readiness
or a migration of an existing front door; ports 80/443 are used when application
routes are later applied. Real systemd activation acceptance remains outstanding.
Moving an existing front door requires the separate probe-guarded cutover below.

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

## macOS Docker router

Docker Desktop must be running. YanPort automatically selects the Docker router
on macOS; override selection only for diagnosis with
`YAN_PORT_ROUTER_DRIVER=native|docker`.

```bash
just setup
just router-install
```

The router is a digest-pinned Caddy 2.11.4 container named
`yan-port-caddy`. It publishes ports 80 and 443 on host loopback only, persists
its local CA in the `yan-port-caddy-data` volume, restarts with Docker Desktop,
and reaches host-run development processes through `host.docker.internal`.
Registry routes remain canonical loopback origins; translation happens only in
the rendered Docker Caddy configuration.

Install, start, stop, uninstall, reload and certificate export validate the
existing container's image, ownership labels, loopback ports, restart policy and
mounts before acting.
Configuration drift requires inspection; even a failed container is not removed
automatically when its configuration differs. Start, reload and certificate
export also verify ownership of the certificate volume. These checks do not
authorize replacing other workloads.

After an application registers the first HTTPS route, install the exact active
root into macOS System Keychain:

```bash
just trust-install
yan-port trust status
```

The trust command prompts through `sudo`, records the exported public root under
YanPort's user state directory, and verifies the same fingerprint in System
Keychain. Removal is exact-fingerprint and explicit:

```bash
just trust-remove
just router-uninstall --yes       # preserves the CA volume
just router-uninstall --yes --purge-data
```

Purging the volume permanently removes the router's private local CA. Normal
stop, restart, and uninstall preserve it.

## License

YanPort is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
