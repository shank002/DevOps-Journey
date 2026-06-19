#!/usr/bin/env bash
# cleanup.sh — undo everything break-things.sh introduced.

set -euo pipefail

echo "=== cleanup.sh ==="

# Kill background python processes from break-things.sh
pkill -f "held_open_" 2>/dev/null && echo "[+] Killed held-open file process" || true
pkill -f "zombie created" 2>/dev/null || true
# The zombie parent was the python3 process holding the sleep
pkill -f "time.sleep(300)" 2>/dev/null && echo "[+] Killed zombie parent process" || true

# Remove SUID binary
rm -f /tmp/suspicious_cat && echo "[+] Removed /tmp/suspicious_cat" || true

# Remove world-writable file
rm -f /tmp/world_writable_file.txt && echo "[+] Removed world-writable file" || true

# Remove cron job
if [[ -f /etc/cron.d/totally-legit ]]; then
  rm -f /etc/cron.d/totally-legit && echo "[+] Removed cron job" || true
fi

# Remove exfil file if it was created
rm -f /tmp/passwd_exfil.txt 2>/dev/null || true

echo ""
echo "Cleanup complete."
