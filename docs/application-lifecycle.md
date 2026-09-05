# Application CLI lifecycle

YanPort owns context identity, leases, exact local routes, and certificate
diagnostics. An application's own CLI owns its process, readiness definition,
logs, signals, and teardown. YanPort must not become a process supervisor for
Remotion Studio, Vite, or another development server.

An application launcher should perform this lifecycle:

```text
ensure context
→ allocate or reuse port
→ start application on that port
→ wait for application-defined readiness
→ apply the YanPort route
→ print the canonical HTTPS URL
→ wait for application shutdown
→ remove the route
→ release the port
```

The route is applied only after readiness succeeds, so the canonical URL is
never advertised before the application can serve it. Cleanup removes the route
before releasing its referenced port. A signal handler must also stop and reap
the application before releasing the lease.

## Reference shell workflow

This example shows the sequencing; a production launcher should express the
same behavior in its native process-management language.

```bash
#!/usr/bin/env bash
set -euo pipefail

service="studio-demo"
context_json="$(yan-port context ensure \
  --project example-app \
  --domain example.localhost \
  --json)"
route_domain="$(python -c \
  'import json,sys; print(json.load(sys.stdin)["route_domain"])' \
  <<<"${context_json}")"
hostname="studio.${route_domain}"
port="$(yan-port port allocate "${service}")"
child_pid=""

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  yan-port route remove "${service}" >/dev/null 2>&1 || true
  if [[ -n "${child_pid}" ]] && kill -0 "${child_pid}" 2>/dev/null; then
    kill "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
  fi
  yan-port port release "${service}" >/dev/null 2>&1 || true
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

example-development-server --host 127.0.0.1 --port "${port}" &
child_pid=$!

ready=false
for _attempt in $(seq 1 80); do
  if ! kill -0 "${child_pid}" 2>/dev/null; then
    wait "${child_pid}"
    exit 1
  fi
  if curl --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 \
    "http://127.0.0.1:${port}/ready" >/dev/null; then
    ready=true
    break
  fi
  sleep 0.25
done
[[ "${ready}" == true ]] || { echo "Application did not become ready" >&2; exit 1; }

yan-port route apply "${service}" \
  --host "${hostname}" \
  --upstream "http://127.0.0.1:${port}" \
  --port-service "${service}" >/dev/null

printf 'Ready: https://%s/\n' "${hostname}"
wait "${child_pid}"
```

`context ensure` and `port allocate` are idempotent for an already-owned
context/service, so a launcher may reuse its lease. It must still verify that
the selected port can be used by the process and must surface startup failures.
If readiness fails, the cleanup trap releases the unused route/lease state.
