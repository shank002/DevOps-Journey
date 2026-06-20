#!/usr/bin/env bash
# setup/cleanup.sh
# Removes everything plant.sh created.

set -euo pipefail

BASE=/tmp/fs-probe-lab
if [ -d "$BASE" ]; then
    rm -rf "$BASE"
    echo "[cleanup] removed $BASE"
else
    echo "[cleanup] $BASE not found, nothing to do"
fi

# Also clean up any leftover temp files from probes
rm -f /tmp/fs-probe-deleteme
rm -rf /tmp/fs-probe-links
echo "[cleanup] done"
