#!/usr/bin/env bash
set -euo pipefail

# Reviewed upstream release from https://github.com/caddyserver/caddy/releases/tag/v2.11.4
caddy_version="2.11.4"
caddy_archive="caddy_${caddy_version}_linux_amd64.tar.gz"
caddy_sha512="8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9"
caddy_url="https://github.com/caddyserver/caddy/releases/download/v${caddy_version}/${caddy_archive}"
install_dir="/usr/local/bin"

usage() {
  printf 'Usage: %s [--install-dir DIRECTORY]\n' "$0"
}

while (($#)); do
  case "$1" in
    --install-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      install_dir="$2"
      shift 2
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

case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) ;;
  *)
    printf 'This pinned installer supports Linux amd64 only; got %s %s\n' \
      "$(uname -s)" "$(uname -m)" >&2
    exit 1
    ;;
esac

if [[ "${install_dir}" == "/usr/local/bin" && "${EUID}" -ne 0 ]]; then
  printf 'Run with sudo when installing to /usr/local/bin.\n' >&2
  exit 1
fi

caddy_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${caddy_tmp_dir}"' EXIT

curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
  "${caddy_url}" --output "${caddy_tmp_dir}/${caddy_archive}"
printf '%s  %s\n' "${caddy_sha512}" "${caddy_tmp_dir}/${caddy_archive}" | sha512sum --check --status
tar --extract --gzip --file "${caddy_tmp_dir}/${caddy_archive}" \
  --directory "${caddy_tmp_dir}" caddy
"${caddy_tmp_dir}/caddy" version | grep --fixed-strings --quiet "v${caddy_version}"

install -d -m 0755 "${install_dir}"
if [[ "${EUID}" -eq 0 ]]; then
  install -o root -g root -m 0755 "${caddy_tmp_dir}/caddy" "${install_dir}/caddy"
else
  install -m 0755 "${caddy_tmp_dir}/caddy" "${install_dir}/caddy"
fi
"${install_dir}/caddy" version
