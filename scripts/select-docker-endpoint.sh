#!/usr/bin/env bash
set -euo pipefail

legacy_container="${1:?legacy container name is required}"
operator="${2:-}"
shift 2 || true
socket_candidates=("$@")

if [[ -n "${DOCKER_HOST:-}" ]]; then
  if docker inspect "${legacy_container}" >/dev/null 2>&1; then
    printf '%s\n' "${DOCKER_HOST}"
    exit 0
  fi
  echo "The explicit DOCKER_HOST does not contain ${legacy_container}." >&2
  exit 1
fi

if ((${#socket_candidates[@]} == 0)) && [[ -n "${operator}" && "${operator}" != root ]]; then
  operator_entry="$(getent passwd "${operator}")"
  operator_uid="$(cut -d: -f3 <<<"${operator_entry}")"
  operator_home="$(cut -d: -f6 <<<"${operator_entry}")"
  socket_candidates=(
    "${operator_home}/.docker/desktop/docker.sock"
    "/run/user/${operator_uid}/docker.sock"
  )
fi

matches=()
if env -u DOCKER_HOST docker inspect "${legacy_container}" >/dev/null 2>&1; then
  matches+=(default)
fi
for docker_socket in "${socket_candidates[@]}"; do
  if [[ -S "${docker_socket}" ]] && \
    DOCKER_HOST="unix://${docker_socket}" docker inspect "${legacy_container}" >/dev/null 2>&1; then
    matches+=("unix://${docker_socket}")
  fi
done

case "${#matches[@]}" in
  1)
    printf '%s\n' "${matches[0]}"
    ;;
  0)
    echo "No Docker endpoint contains ${legacy_container}." >&2
    exit 1
    ;;
  *)
    printf 'Multiple Docker endpoints contain %s: %s\n' \
      "${legacy_container}" "${matches[*]}" >&2
    echo "Preserve the intended DOCKER_HOST explicitly and retry." >&2
    exit 1
    ;;
esac
