#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo scripts/install-service.sh" >&2
  exit 1
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
operator="${SUDO_USER:-}"

if [[ ! -x /usr/local/bin/caddy ]]; then
  echo "/usr/local/bin/caddy is missing; install and verify the pinned binary first" >&2
  exit 1
fi

getent group yan-port >/dev/null || groupadd --system yan-port
if [[ -n "${operator}" && "${operator}" != root ]]; then
  usermod --append --groups yan-port "${operator}"
fi
id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/yan-port --shell /usr/sbin/nologin caddy

install -d -o caddy -g yan-port -m 2770 /var/lib/yan-port
if [[ ! -e /var/lib/yan-port/Caddyfile ]]; then
  install -o caddy -g yan-port -m 0640 "${repo_dir}/deploy/bootstrap.Caddyfile" /var/lib/yan-port/Caddyfile
fi
install -o root -g root -m 0644 "${repo_dir}/deploy/yan-port-caddy.service" /etc/systemd/system/yan-port-caddy.service
install -o root -g root -m 0644 "${repo_dir}/deploy/yan-port-caddy-cutover.service" /etc/systemd/system/yan-port-caddy-cutover.service
systemctl daemon-reload

echo "Installed yan-port-caddy.service without starting it. Re-login to refresh group membership."
