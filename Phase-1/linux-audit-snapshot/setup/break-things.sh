#!/usr/bin/env bash
# break-things.sh — deliberately introduce security findings into a VM.
#
# Run this BEFORE snapshot.sh to give it something to find.
# Run cleanup.sh AFTER to restore the system.
#
# ONLY run this on a throwaway VM or VM with a snapshot taken.
# DO NOT run on any system you care about.

set -euo pipefail

echo "=== break-things.sh ==="
echo "Introducing deliberate findings. Run on a VM only."
echo ""

# 1. SUID binary
# Normally only trusted system binaries have SUID. Placing an unexpected
# one here simulates a planted backdoor or misconfigured install.
cp /bin/cat /tmp/suspicious_cat
chmod +s /tmp/suspicious_cat
echo "[+] Created SUID binary: /tmp/suspicious_cat"
echo "    Try: ls -la /tmp/suspicious_cat  -- look for the 's' in rwsr-xr-x"

# 2. World-writable file outside /tmp
# /tmp is expected to be world-writable. /etc or application dirs are not.
touch /tmp/world_writable_file.txt
chmod 777 /tmp/world_writable_file.txt
echo "[+] Created world-writable file: /tmp/world_writable_file.txt"

# 3. Deleted file held open (space not reclaimed)
# This simulates a log file that was rotated/deleted but a process
# still holds the FD open — occupying disk space with no visible name.
python3 - << 'PYEOF' &
import tempfile, os, time, sys

f = tempfile.NamedTemporaryFile(
    prefix="held_open_",
    suffix=".log",
    dir="/tmp",
    delete=False
)
f.write(b"This file is deleted but its FD is held open.\n" * 1000)
f.flush()

# Delete the name (dentry) — inode still exists because FD is open
name = f.name
os.unlink(name)

print(f"[+] Deleted {name} but holding FD open (PID {os.getpid()})")
print(f"    Run: lsof | grep deleted   -- it should appear")
sys.stdout.flush()

# Hold it open for 5 minutes
time.sleep(300)
PYEOF
sleep 1  # give python a moment to print its message

# 4. Zombie process
# Fork a child, let it exit, but parent never calls wait().
# Child becomes zombie — visible in ps aux as state Z.
python3 - << 'PYEOF' &
import os, time, sys

parent_pid = os.getpid()
child_pid = os.fork()

if child_pid == 0:
    # Child: exit immediately
    os._exit(0)
else:
    # Parent: never call wait() — child becomes zombie
    print(f"[+] Zombie created. Parent PID={parent_pid}, zombie child PID={child_pid}")
    print(f"    Run: ps aux | awk '$8==\"Z\"'   -- zombie should appear")
    sys.stdout.flush()
    time.sleep(300)
PYEOF
sleep 1

# 5. Suspicious cron job
# Persistence via cron is a classic attacker technique.
# This writes a harmless cron job to demonstrate the detection.
CRON_FILE="/etc/cron.d/totally-legit"
if [[ $EUID -eq 0 ]]; then
  cat > "$CRON_FILE" << 'CRONEOF'
# totally-legit — this should be detected by the audit script
* * * * * root /tmp/suspicious_cat /etc/passwd > /tmp/passwd_exfil.txt 2>/dev/null
CRONEOF
  echo "[+] Created suspicious cron job: $CRON_FILE"
  echo "    Run: cat $CRON_FILE"
else
  echo "[!] Skipping cron job (need root). Re-run with sudo to include this finding."
fi

echo ""
echo "Findings introduced. Now run:"
echo "  sudo ./snapshot.sh"
echo "Then run ./cleanup.sh when done."
