#!/bin/bash
# Start the MITRE CALDERA adversary-emulation server that the `caldera` tool
# wrapper (tools/simulation/caldera.py) talks to over its v2 REST API.
#
# Reads config from the project .env so the server's *red* API key and port
# match what the wrapper sends (CALDERA_API_KEY / CALDERA_URL). Used both
# directly (foreground) and by scripts/caldera.service.

set -e
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

CALDERA_DIR="${CALDERA_DIR:-$REPO_DIR/caldera}"

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

if [ ! -d "$CALDERA_DIR" ]; then
    echo "CALDERA is not installed at $CALDERA_DIR." >&2
    echo "Run ./setup_kali.sh (it clones + installs CALDERA), or set CALDERA_DIR." >&2
    exit 1
fi

# Derive the listen port from CALDERA_URL (e.g. http://127.0.0.1:8888).
CALDERA_URL="${CALDERA_URL:-http://127.0.0.1:8888}"
CALDERA_PORT="$(printf '%s' "$CALDERA_URL" | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
[ -z "$CALDERA_PORT" ] && CALDERA_PORT=8888
API_KEY_RED="${CALDERA_API_KEY:-ADMIN123}"

# Regenerate conf/local.yml from .env on every start so the red API key stays
# in sync with what the wrapper sends in the KEY header (same philosophy as
# start_msfrpc.sh reading creds from .env). Salt/encryption key are fixed for a
# persistent lab install — insecure, lab use only.
mkdir -p "$CALDERA_DIR/conf"
cat > "$CALDERA_DIR/conf/local.yml" <<EOF
host: 0.0.0.0
port: ${CALDERA_PORT}
api_key_red: ${API_KEY_RED}
api_key_blue: BLUEADMIN123
crypt_salt: redteam-engine-lab-salt
encryption_key: redteam-engine-lab-key
users:
  red:
    red: admin
  blue:
    blue: admin
EOF

cd "$CALDERA_DIR"

# --insecure loads the merged default.yml + local.yml without prompting.
# --build bundles the VueJS UI. The tool wrapper only needs the REST API, but
# the UI is how you get sandcat agent-deploy commands for the lab targets, so
# it is built by default. npm caches the build, so only the first start is slow.
# Set CALDERA_BUILD=0 to skip it once the UI is built and start faster.
BUILD_FLAG="--build"
[ "${CALDERA_BUILD:-1}" = "0" ] && BUILD_FLAG=""

echo "Starting CALDERA on port ${CALDERA_PORT} (UI login: red / admin)"
# shellcheck disable=SC2086
exec .venv/bin/python server.py --insecure $BUILD_FLAG --log INFO
