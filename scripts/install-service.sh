#!/usr/bin/env bash
set -euo pipefail

check_only=false
case "${1:-}" in
  --check) check_only=true ;;
  "") ;;
  *) echo "usage: install-service.sh [--check]" >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo "usage: install-service.sh [--check]" >&2; exit 2; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo scripts/install-service.sh" >&2
  exit 1
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
operator="${SUDO_USER:-}"

if [[ "$check_only" == false && ! -x /usr/local/bin/caddy ]]; then
  echo "/usr/local/bin/caddy is missing; install and verify the pinned binary first" >&2
  exit 1
fi

for unit in yan-port-caddy.service yan-port-caddy-cutover.service; do
  for directory in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    if [[ -e "$directory/$unit.d" || -L "$directory/$unit.d" ||
          ( "$directory" != /etc/systemd/system &&
            ( -e "$directory/$unit" || -L "$directory/$unit" ) ) ]]; then
      echo "Existing systemd override or competing unit requires explicit review: $directory/$unit" >&2
      exit 1
    fi
  done
  destination="/etc/systemd/system/$unit"
  if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    echo "Existing unit destination needs explicit repair: $destination" >&2
    exit 1
  fi
  if [[ -f "$destination" ]] && ! cmp -s "${repo_dir}/deploy/$unit" "$destination"; then
    echo "Existing unit differs from YanPort; preserve it and resolve explicitly: $destination" >&2
    exit 1
  fi
done
if [[ -L /var/lib/yan-port || ( -e /var/lib/yan-port && ! -d /var/lib/yan-port ) ||
      -L /var/lib/yan-port/Caddyfile ||
      ( -e /var/lib/yan-port/Caddyfile && ! -f /var/lib/yan-port/Caddyfile ) ]]; then
  echo "Existing YanPort state destination needs explicit repair" >&2
  exit 1
fi

uid=""
if account="$(getent passwd caddy)"; then
  IFS=: read -r name password uid gid description home login_shell <<< "$account"
  if [[ "$account" == *$'\n'* || "$name" != caddy ||
        ! "$uid" =~ ^[1-9][0-9]*$ || ! "$gid" =~ ^[1-9][0-9]*$ ||
        "$home" != /var/lib/yan-port ||
        ( "$login_shell" != /usr/sbin/nologin && "$login_shell" != /sbin/nologin ) ]]; then
    echo "Existing caddy account is not the dedicated YanPort service account; preserve it and resolve explicitly" >&2
    exit 1
  fi
  groups="$(id -nG caddy)"
  for group in $groups; do
    case "$group" in
      root|sudo|wheel|docker)
        echo "Existing caddy account has privileged group membership: $group" >&2
        exit 1 ;;
    esac
  done
else
  result=$?
  if [[ "$result" -ne 2 ]]; then
    echo "Cannot inspect the caddy account; resolve account lookup before provisioning" >&2
    exit 1
  fi
fi

if group_entry="$(getent group yan-port)"; then
  IFS=: read -r group_name group_password state_gid members <<< "$group_entry"
  [[ "$group_name" == yan-port && "$state_gid" =~ ^[1-9][0-9]*$ && "$group_entry" != *$'\n'* ]] || {
    echo "Existing yan-port group requires explicit review" >&2; exit 1;
  }
else
  result=$?
  [[ "$result" -eq 2 ]] || { echo "Cannot inspect the yan-port group" >&2; exit 1; }
  state_gid=""
fi

for path in /var/lib/yan-port /var/lib/yan-port/Caddyfile; do
  if [[ -e "$path" ]]; then
    [[ -n "${uid:-}" && -n "$state_gid" && "$(stat -c '%u:%g' "$path")" == "$uid:$state_gid" ]] || {
      echo "Existing YanPort state has unverified ownership; preserve it and resolve explicitly: $path" >&2
      exit 1
    }
  fi
done

if [[ "$check_only" == true ]]; then
  echo "Native service preflight passed; no accounts or services changed."
  exit 0
fi

[[ -n "$state_gid" ]] || groupadd --system yan-port
if [[ -n "${operator}" && "${operator}" != root ]]; then
  usermod --append --groups yan-port "${operator}"
fi
id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/yan-port --shell /usr/sbin/nologin caddy

if [[ ! -d /var/lib/yan-port ]]; then
  install -d -o caddy -g yan-port -m 2770 /var/lib/yan-port
fi
if [[ ! -e /var/lib/yan-port/Caddyfile ]]; then
  install -o caddy -g yan-port -m 0640 "${repo_dir}/deploy/bootstrap.Caddyfile" /var/lib/yan-port/Caddyfile
fi
for unit in yan-port-caddy.service yan-port-caddy-cutover.service; do
  if [[ ! -e "/etc/systemd/system/$unit" ]]; then
    install -o root -g root -m 0644 "${repo_dir}/deploy/$unit" "/etc/systemd/system/$unit"
  fi
done
systemctl daemon-reload

echo "Installed yan-port-caddy.service without starting it. Re-login to refresh group membership."
