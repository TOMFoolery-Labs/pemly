#!/bin/bash
# Compatibility shim.
#
# Pemly no longer installs onto the host with systemd, nginx and a virtualenv; it
# runs as a Docker Compose stack. The installer moved to deploy/install.sh.
#
# This file exists only so that the one-liner published with older releases keeps
# working. It forwards every argument to the current installer.
set -euo pipefail

INSTALLER_URL="https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/install.sh"
LOCAL_INSTALLER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/install.sh"

echo "[INFO] deploy/systemd/install.sh has moved to deploy/install.sh; forwarding..."

if [[ -f "${LOCAL_INSTALLER}" ]]; then
    exec bash "${LOCAL_INSTALLER}" "$@"
fi

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
curl -fsSL "${INSTALLER_URL}" -o "${tmp}"
exec bash "${tmp}" "$@"
