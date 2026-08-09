#!/bin/bash
# Start msfrpcd reading credentials from the project .env file.
# Used both directly (foreground) and by scripts/msfrpcd.service.

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

exec msfrpcd \
    -U "${MSF_RPC_USER:-msf}" \
    -P "${MSF_RPC_PASS:-changeme}" \
    -a "${MSF_RPC_HOST:-127.0.0.1}" \
    -p "${MSF_RPC_PORT:-55553}" \
    -S \
    -f
