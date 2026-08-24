#!/bin/bash
# setup_kali.sh — one-shot installer for AI Red Team Engine on Kali Linux.
#
# After cloning the repo on a fresh Kali VM:
#   chmod +x setup_kali.sh && ./setup_kali.sh
#
# Installs all OS-level offensive tooling, creates a Python venv, installs
# Python dependencies, and starts the Postgres + Neo4j containers.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

echo "--- [1/7] Updating apt index ---"
sudo apt update

echo "--- [2/7] Installing Python, Docker, build tools ---"
sudo apt install -y \
    python3 python3-pip python3-venv \
    libpq-dev build-essential git \
    docker.io docker-compose \
    libxml2-dev libxslt1-dev zlib1g-dev
# libxml2-dev/libxslt1-dev/zlib1g-dev: CALDERA pins lxml~=4.9.1, which ships no
# wheel for Python 3.13, so pip builds it from source and needs these headers.

echo "--- [3/7] Installing offensive security tooling ---"
sudo apt install -y \
    nmap gobuster ffuf nikto sqlmap theharvester \
    metasploit-framework \
    hashcat hydra john

# OpenVAS / Greenbone (gvm-tools provides gvm-cli used by openvas wrapper;
# `gvm` pulls the full gvmd/openvasd stack — ~1 GB plus a long initial sync).
sudo apt install -y gvm gvm-tools

# Active Directory: crackmapexec on older Kali, netexec on newer.
sudo apt install -y crackmapexec || sudo apt install -y netexec

# Nuclei (Go-based; apt version often stale — fall back to GitHub release).
if ! command -v nuclei >/dev/null 2>&1; then
    echo "--- Installing Nuclei from release ---"
    sudo apt install -y nuclei || (
        TMP=$(mktemp -d) && cd "$TMP"
        wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip
        unzip -q nuclei_3.3.5_linux_amd64.zip
        sudo mv nuclei /usr/local/bin/
        cd "$REPO_DIR" && rm -rf "$TMP"
    )
fi

# Rustscan (Rust binary distributed as .deb).
if ! command -v rustscan >/dev/null 2>&1; then
    echo "--- Installing Rustscan from release ---"
    TMP=$(mktemp -d) && cd "$TMP"
    wget -q https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb
    sudo dpkg -i rustscan_2.3.0_amd64.deb
    cd "$REPO_DIR" && rm -rf "$TMP"
fi

echo "--- [4/7] Enabling Docker daemon ---"
sudo systemctl enable --now docker
if ! groups "$USER" | grep -q '\bdocker\b'; then
    sudo usermod -aG docker "$USER"
    DOCKER_GROUP_ADDED=1
fi

echo "--- [5/7] Creating Python venv and installing dependencies ---"
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# pwncat-cs is driven as a CLI subprocess by tools/post_exploit/pwncat.py, so it
# only needs to be on PATH. It is NOT installed into .venv: it pins
# packaging<21.0, which is unsolvable against the engine's modern dependencies.
# pipx gives it its own isolated environment.
if ! command -v pwncat-cs >/dev/null 2>&1; then
    echo "--- Installing pwncat-cs (isolated, via pipx) ---"
    sudo apt install -y pipx
    pipx install pwncat-cs
    pipx ensurepath
fi

echo "--- [6/7] Bootstrapping local config ---"
if [ ! -f .env ]; then
    cp .env.example .env
    echo "    Created .env from .env.example — edit it and set ANTHROPIC_API_KEY."
fi

echo "--- [7/7] Installing CALDERA (adversary-emulation server) ---"
# The `caldera` tool wrapper drives a CALDERA server over REST. CALDERA is a
# required component of this project (see the tool stack in ARCHITECTURE.md,
# Tool Stack), not an optional extra.
#
# Cloned into ./caldera with its own venv so its pinned deps don't collide
# with the engine's .venv. Pinned to a release tag rather than tracking master
# so setup is reproducible — bump CALDERA_TAG to upgrade deliberately.
CALDERA_TAG="${CALDERA_TAG:-5.3.0}"

# NOTE: calling this from an `if` suppresses `set -e` inside the whole function
# body, and the function's exit status would otherwise be that of its LAST
# command. Every step therefore needs an explicit `|| return 1`, or a failed
# clone would still report success and skip the warning block below.
install_caldera() {
    # Node is needed for `server.py --build`, which bundles the VueJS UI — the
    # UI is how you generate sandcat agent-deploy commands for the targets.
    # Go (>=1.19) is needed by the sandcat plugin, which compiles the agent
    # binaries on demand; without it CALDERA logs "go does not meet the minimum
    # version" and STEP 6C (deploying agents onto lab targets) cannot proceed.
    sudo apt install -y nodejs npm golang-go || return 1

    if [ -d caldera/.git ]; then
        echo "    CALDERA already present at ./caldera — skipping clone."
        echo "    (To re-pin: rm -rf caldera && re-run this script.)"
    else
        git clone https://github.com/apache/caldera.git --recursive \
            --branch "$CALDERA_TAG" caldera || return 1
    fi
    if [ ! -d caldera/.venv ]; then
        python3 -m venv caldera/.venv || return 1
    fi
    caldera/.venv/bin/pip install --upgrade pip || return 1

    # CALDERA 5.3.0 pins lxml~=4.9.1, which has no wheel for Python 3.13 and
    # cannot be compiled from source on current Kali: 4.9.x predates both the
    # CPython 3.13 _PyInterpreterState_GetConfig change and the libxml2 2.12+
    # xmlStructuredErrorFunc signature change (Kali ships libxml2 2.15). Relax
    # that one pin to a release with a prebuilt cp313 wheel; the rest of the
    # pins are honoured as-is.
    CALDERA_REQS=$(mktemp)
    sed 's/^lxml~=.*/lxml>=5.3/' caldera/requirements.txt > "$CALDERA_REQS" || return 1
    caldera/.venv/bin/pip install -r "$CALDERA_REQS" || { rm -f "$CALDERA_REQS"; return 1; }
    rm -f "$CALDERA_REQS"

    # Not in CALDERA's requirements.txt, but its `builder` plugin imports it and
    # fails to load without it ("No module named 'docker'").
    caldera/.venv/bin/pip install docker || return 1

    echo "    CALDERA $CALDERA_TAG installed."
}
if install_caldera; then
    CALDERA_OK=1
else
    CALDERA_OK=0
fi

echo
echo "============================================================"
echo " Setup complete."
echo
echo " Next steps (run each in an activated venv):"
echo "   1. Edit .env and set ANTHROPIC_API_KEY."
echo "      Check ALLOWED_TARGET_RANGES covers your target's IP."
echo "   2. Start the databases:    docker compose up -d"
echo "   3. Run DB migrations:      alembic upgrade head"
echo "   4. Smoke-test:             pytest -v"
echo
echo "   Leave these running, each in its own terminal:"
echo "   5. Metasploit RPC:         ./scripts/start_msfrpc.sh"
echo "   6. CALDERA server:         ./scripts/start_caldera.sh"
echo "      (first start builds the UI and is slow)"
echo
echo "   7. Run a session:          python main.py run --target <ip>"
echo
echo " Full walkthrough, including target VM setup: INSTRUCTIONS.txt"
echo
if [ "${DOCKER_GROUP_ADDED:-0}" = "1" ]; then
    echo " NOTE: you were added to the 'docker' group. Log out and back in"
    echo "       (or run 'newgrp docker') before using docker commands."
    echo
fi
if [ "${CALDERA_OK:-0}" != "1" ]; then
    echo " ***  CALDERA INSTALL FAILED  ***************************"
    echo " CALDERA is a required component of this project, not an"
    echo " optional extra. The rest of the engine will run without"
    echo " it, but the 'caldera' tool will error until it is fixed."
    echo
    echo " Retry just this part:"
    echo "   rm -rf caldera"
    echo "   git clone https://github.com/apache/caldera.git \\"
    echo "       --recursive --branch 5.3.0 caldera"
    echo "   python3 -m venv caldera/.venv"
    echo "   caldera/.venv/bin/pip install -r caldera/requirements.txt"
    echo " See INSTRUCTIONS.txt STEP 6B."
    echo " ********************************************************"
fi
echo "============================================================"
