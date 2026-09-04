#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
final_config="/var/lib/yan-port/Caddyfile"
legacy_container=""
cutover_http_port=18080
cutover_https_port=18443
confirmed=false
probes=()

usage() {
  cat <<'EOF'
Usage: sudo scripts/cutover-native-caddy.sh --yes --legacy-container NAME
       --probe URL [--probe URL ...] [--final-config PATH]

Hands local HTTP/HTTPS traffic from the named Docker Caddy container to the
native yan-port-caddy.service. The final config must already be staged.
EOF
}

while (($#)); do
  case "$1" in
    --probe)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      probes+=("$2")
      shift 2
      ;;
    --final-config)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      final_config="$2"
      shift 2
      ;;
    --legacy-container)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      legacy_container="$2"
      shift 2
      ;;
    --yes)
      confirmed=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { echo "Cutover must run as root." >&2; exit 1; }
[[ "${confirmed}" == true ]] || { echo "Cutover requires --yes." >&2; exit 1; }
[[ -n "${legacy_container}" ]] || {
  echo "Cutover requires --legacy-container NAME." >&2
  exit 1
}
((${#probes[@]} > 0)) || { echo "Cutover requires at least one --probe URL." >&2; exit 1; }
[[ -s "${final_config}" ]] || { echo "Missing staged final config: ${final_config}" >&2; exit 1; }

for command in caddy curl docker nft sed systemctl update-ca-certificates; do
  command -v "${command}" >/dev/null || { echo "Missing command: ${command}" >&2; exit 1; }
done

docker_endpoint="$("${script_dir}/select-docker-endpoint.sh" "${legacy_container}" "${SUDO_USER:-}")"
if [[ "${docker_endpoint}" == default ]]; then
  unset DOCKER_HOST
else
  export DOCKER_HOST="${docker_endpoint}"
fi
docker inspect "${legacy_container}" >/dev/null 2>&1 || {
  echo "Legacy container does not exist: ${legacy_container}" >&2
  exit 1
}
[[ "$(docker inspect --format '{{.State.Running}}' "${legacy_container}")" == true ]] || {
  echo "Legacy container is not running: ${legacy_container}" >&2
  exit 1
}
systemctl is-active --quiet yan-port-caddy.service && {
  echo "Final YanPort service is already active; refusing a first-cutover workflow." >&2
  exit 1
}
systemctl is-enabled --quiet yan-port-caddy.service && {
  echo "Final YanPort service is already enabled; refusing a first-cutover workflow." >&2
  exit 1
}
if nft list table inet yan_port_cutover >/dev/null 2>&1; then
  echo "The yan_port_cutover nftables table already exists; remove or investigate it first." >&2
  exit 1
fi

cutover_config="/var/lib/yan-port/Caddyfile.cutover"
cutover_root="/var/lib/yan-port/data/caddy/pki/authorities/local/root.crt"
system_root="/usr/local/share/ca-certificates/yan-port-local-root.crt"
probe_failures="/run/yan-port-cutover-probe-failures.log"
probe_pid=""

stop_probe_loop() {
  if [[ -n "${probe_pid}" ]]; then
    kill "${probe_pid}" >/dev/null 2>&1 || true
    wait "${probe_pid}" 2>/dev/null || true
    probe_pid=""
  fi
}

wait_for_probes() {
  local attempt url
  for attempt in $(seq 1 60); do
    for url in "${probes[@]}"; do
      if ! curl --fail --silent --show-error --location --connect-timeout 1 --max-time 5 \
        "${url}" >/dev/null; then
        sleep 0.25
        continue 2
      fi
    done
    return 0
  done
  echo "Probes did not become healthy." >&2
  return 1
}

start_probe_loop() {
  : >"${probe_failures}"
  (
    while true; do
      for url in "${probes[@]}"; do
        if ! curl --fail --silent --show-error --location --connect-timeout 1 --max-time 5 \
          "${url}" >/dev/null 2>&1; then
          printf '%(%FT%T%z)T %s\n' -1 "${url}" >>"${probe_failures}"
        fi
      done
      sleep 0.05
    done
  ) &
  probe_pid=$!
}

rollback() {
  local exit_code=$?
  trap - ERR INT TERM
  stop_probe_loop
  echo "Cutover failed; restoring the legacy listener." >&2
  if systemctl is-active --quiet yan-port-caddy.service; then
    systemctl stop yan-port-caddy.service || true
  fi
  if systemctl is-enabled --quiet yan-port-caddy.service; then
    systemctl disable yan-port-caddy.service || true
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "${legacy_container}" 2>/dev/null || true)" != true ]]; then
    docker start "${legacy_container}" >/dev/null || true
    for _attempt in $(seq 1 40); do
      [[ "$(docker inspect --format '{{.State.Running}}' "${legacy_container}" 2>/dev/null || true)" == true ]] && break
      sleep 0.25
    done
  fi
  if nft list table inet yan_port_cutover >/dev/null 2>&1; then
    nft delete table inet yan_port_cutover || true
  fi
  systemctl stop yan-port-caddy-cutover.service || true
  exit "${exit_code}"
}
trap rollback ERR INT TERM

sed \
  -e 's#admin unix//run/yan-port/caddy-admin.sock|0660#admin unix//run/yan-port-cutover/caddy-admin.sock|0660#' \
  -e "s/http_port 80/http_port ${cutover_http_port}/" \
  -e "s/https_port 443/https_port ${cutover_https_port}/" \
  "${final_config}" >"${cutover_config}"
chown caddy:yan-port "${cutover_config}"
chmod 0640 "${cutover_config}"
caddy validate --config "${cutover_config}" --adapter caddyfile >/dev/null

systemctl start yan-port-caddy-cutover.service
for _attempt in $(seq 1 80); do
  [[ -S /run/yan-port-cutover/caddy-admin.sock ]] && break
  sleep 0.25
done
[[ -S /run/yan-port-cutover/caddy-admin.sock ]] || {
  echo "Temporary Caddy admin socket did not appear." >&2
  false
}

# Force certificate issuance for every HTTPS probe before trusting the CA.
for url in "${probes[@]}"; do
  probe_host="$(sed -E 's#^https?://([^/:]+).*#\1#' <<<"${url}")"
  curl --insecure --fail --silent --show-error --connect-timeout 1 --max-time 5 \
    --resolve "${probe_host}:${cutover_https_port}:127.0.0.1" \
    "https://${probe_host}:${cutover_https_port}/" >/dev/null || true
done
[[ -s "${cutover_root}" ]] || { echo "YanPort local CA root was not created." >&2; false; }
install -o root -g root -m 0644 "${cutover_root}" "${system_root}"
update-ca-certificates >/dev/null

nft add table inet yan_port_cutover
nft 'add chain inet yan_port_cutover output { type nat hook output priority dstnat; policy accept; }'
nft add rule inet yan_port_cutover output ip daddr 127.0.0.0/8 tcp dport 80 redirect to :"${cutover_http_port}"
nft add rule inet yan_port_cutover output ip6 daddr ::1 tcp dport 80 redirect to :"${cutover_http_port}"
nft add rule inet yan_port_cutover output ip daddr 127.0.0.0/8 tcp dport 443 redirect to :"${cutover_https_port}"
nft add rule inet yan_port_cutover output ip6 daddr ::1 tcp dport 443 redirect to :"${cutover_https_port}"
wait_for_probes
start_probe_loop

docker stop --time 10 "${legacy_container}" >/dev/null
systemctl enable yan-port-caddy.service
systemctl start yan-port-caddy.service
systemctl is-active --quiet yan-port-caddy.service
systemctl is-enabled --quiet yan-port-caddy.service

# The final listener is ready before this single ruleset deletion hands traffic
# to it. The temporary listener remains alive until all post-handoff probes pass.
nft delete table inet yan_port_cutover
wait_for_probes
sleep 1
stop_probe_loop
if [[ -s "${probe_failures}" ]]; then
  echo "At least one new HTTP request failed during cutover:" >&2
  cat "${probe_failures}" >&2
  false
fi

systemctl stop yan-port-caddy-cutover.service
rm -f "${cutover_config}" "${probe_failures}"
trap - ERR INT TERM
echo "YanPort cutover completed with zero failed probe requests."
