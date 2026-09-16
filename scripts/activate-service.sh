#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 && "$1" == --yes ]] || {
  echo "usage: activate-service.sh --yes" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "Native activation requires sudo authentication" >&2; exit 1; }
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$repo_dir/scripts/install-service.sh" --check
cmp -s "$repo_dir/deploy/yan-port-caddy.service" /etc/systemd/system/yan-port-caddy.service || {
  echo "Provision the matching native service before activation" >&2; exit 1;
}
cmp -s "$repo_dir/deploy/bootstrap.Caddyfile" /var/lib/yan-port/Caddyfile || {
  echo "Fresh activation requires the unchanged bootstrap; existing routes require explicit review" >&2
  exit 1
}
active="$(systemctl is-active yan-port-caddy.service || true)"
enabled="$(systemctl is-enabled yan-port-caddy.service || true)"
case "$active:$enabled" in
  active:enabled|active:disabled|inactive:enabled|inactive:disabled) ;;
  *) echo "Unexpected native service state: $active/$enabled; inspect it before activation" >&2; exit 1 ;;
esac

restore_on_failure() {
  result=$?
  trap - EXIT
  if [[ "$result" -ne 0 ]]; then
    if [[ "$active" == inactive ]]; then
      systemctl stop yan-port-caddy.service || echo "Rollback could not stop the native service" >&2
    fi
    if [[ "$enabled" == disabled ]]; then
      systemctl disable yan-port-caddy.service || echo "Rollback could not restore disabled startup" >&2
    fi
  fi
  exit "$result"
}
trap restore_on_failure EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$active" == active ]] || systemctl start yan-port-caddy.service
systemctl is-active --quiet yan-port-caddy.service || {
  echo "Native service did not become active" >&2; exit 1;
}
if ! response="$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1:2018/)" ||
   [[ "$response" != "YanPort ready" ]]; then
  echo "Native bootstrap health check failed" >&2
  exit 1
fi
[[ "$enabled" == enabled ]] || systemctl enable yan-port-caddy.service
systemctl is-enabled --quiet yan-port-caddy.service || {
  echo "Native service startup was not enabled" >&2; exit 1;
}
echo "Native bootstrap active and enabled; application routes and HTTPS trust are not yet verified."
