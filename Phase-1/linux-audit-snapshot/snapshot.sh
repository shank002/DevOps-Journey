#!/usr/bin/env bash
# linux-audit-snapshot: point-in-time security snapshot of a Linux system.
# Covers: filesystem, processes, users/groups, logs & auditing.
#
# Usage:
#   ./snapshot.sh                  # write report to /tmp/
#   ./snapshot.sh --out ./report.txt
#   ./snapshot.sh --quiet          # suppress stdout, only write file
#   sudo ./snapshot.sh             # run with sudo for full access (shadow, auditd)
#
# Tested on: Ubuntu 22.04, Debian 12

set -euo pipefail
IFS=$'\n\t'

# ── Argument parsing ────────────────────────────────────────────────────────
OUT_FILE=""
QUIET=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)  OUT_FILE="$2"; shift 2 ;;
    --quiet) QUIET=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Setup ───────────────────────────────────────────────────────────────────
TMPFILE=$(mktemp /tmp/audit-tmp-XXXXXX)
trap 'rm -f "$TMPFILE"' EXIT   # always clean temp file; final mv happens below

# Write to temp file AND stdout (unless --quiet)
emit() {
  if [[ "$QUIET" == true ]]; then
    printf '%s\n' "$*" >> "$TMPFILE"
  else
    printf '%s\n' "$*" | tee -a "$TMPFILE"
  fi
}

section() {
  emit ""
  emit "════════════════════════════════════════════════════════════"
  emit "  $*"
  emit "════════════════════════════════════════════════════════════"
}

sub() {
  emit ""
  emit "── $* ──"
}

warn_emit() {
  emit "[!] $*"
}

ok_emit() {
  emit "[✓] $*"
}

# ── Header ──────────────────────────────────────────────────────────────────
emit "linux-audit-snapshot"
emit "Generated : $(date '+%Y-%m-%d %H:%M:%S %Z')"
emit "Hostname  : $(hostname -f 2>/dev/null || hostname)"
emit "Kernel    : $(uname -r)"
emit "Running as: $(id)"
emit ""

# ── SECTION 1: FILESYSTEM ───────────────────────────────────────────────────
section "FILESYSTEM"

sub "Disk & inode usage"
# df -i shows inode usage alongside block usage.
# A full inode table produces "No space left" even when df -h shows free space.
emit "Blocks:"
df -h --output=source,size,used,avail,pcent,target 2>/dev/null | tee -a "$TMPFILE" || df -h | tee -a "$TMPFILE"
emit ""
emit "Inodes:"
df -i --output=source,iused,iavail,ipcent,target 2>/dev/null | tee -a "$TMPFILE" || df -i | tee -a "$TMPFILE"

sub "SUID binaries (run as file owner, often root)"
# The kernel checks effective UID on every syscall.
# SUID flips eUID to the file owner for the duration of execution.
# Any SUID binary that can spawn a shell = potential root escalation.
SUID_BINS=$(find / -xdev -perm -4000 -type f 2>/dev/null | sort)
SUID_COUNT=$(echo "$SUID_BINS" | grep -c . || true)
emit "Found $SUID_COUNT SUID binaries:"
echo "$SUID_BINS" | while IFS= read -r f; do
  ls -la "$f" 2>/dev/null && emit ""
done | tee -a "$TMPFILE" || true

sub "SGID binaries (run as file group)"
SGID_BINS=$(find / -xdev -perm -2000 -type f 2>/dev/null | sort)
SGID_COUNT=$(echo "$SGID_BINS" | grep -c . || true)
emit "Found $SGID_COUNT SGID binaries:"
echo "$SGID_BINS" | while IFS= read -r f; do
  ls -la "$f" 2>/dev/null
done | tee -a "$TMPFILE" || true

sub "World-writable files (any user can modify or replace)"
# World-writable + SUID = instant privilege escalation.
# World-writable in /etc = config tampering.
WW_FILES=$(find / -xdev -type f -perm -0002 2>/dev/null \
  | grep -Ev '^/proc|^/sys|^/dev|^/run' \
  | sort)
WW_COUNT=$(echo "$WW_FILES" | grep -c . || true)
if [[ $WW_COUNT -eq 0 ]]; then
  ok_emit "No world-writable files found outside /proc /sys /dev /run"
else
  warn_emit "$WW_COUNT world-writable files:"
  echo "$WW_FILES" | tee -a "$TMPFILE"
fi

sub "World-writable directories"
WW_DIRS=$(find / -xdev -type d -perm -0002 2>/dev/null \
  | grep -Ev '^/proc|^/sys|^/dev|^/run|^/tmp$|^/var/tmp$' \
  | sort)
WW_DIR_COUNT=$(echo "$WW_DIRS" | grep -c . || true)
if [[ $WW_DIR_COUNT -eq 0 ]]; then
  ok_emit "No unexpected world-writable directories"
else
  warn_emit "$WW_DIR_COUNT unexpected world-writable directories:"
  echo "$WW_DIRS" | tee -a "$TMPFILE"
fi

sub "Deleted files still held open (disk space not reclaimed)"
# rm = unlink(): removes the directory entry (dentry) but not the inode.
# The inode is freed only when both link count AND open FD count reach 0.
# A process writing to a deleted log file leaks space until restart.
if command -v lsof &>/dev/null; then
  DELETED=$(lsof 2>/dev/null | awk '$4 ~ /[0-9]/ && /deleted/' | awk '{printf "%-20s PID=%-8s %s\n", $1, $2, $NF}')
  if [[ -z "$DELETED" ]]; then
    ok_emit "No deleted files currently held open"
  else
    warn_emit "Deleted files still consuming disk:"
    emit "$DELETED"
  fi
else
  emit "(lsof not installed — skipping)"
fi

# ── SECTION 2: PROCESSES ────────────────────────────────────────────────────
section "PROCESSES"

sub "Zombie processes (Z state — parent not calling wait())"
# A zombie holds no memory/CPU but keeps a PID slot + kernel table entry.
# If PID table fills (cat /proc/sys/kernel/pid_max), no new processes can be created.
ZOMBIES=$(ps aux | awk '$8 == "Z" {print $2, $11}')
if [[ -z "$ZOMBIES" ]]; then
  ok_emit "No zombie processes"
else
  warn_emit "Zombie processes found:"
  emit "PID        COMMAND"
  emit "$ZOMBIES"
fi

sub "D-state processes (uninterruptible sleep — cannot be killed)"
# D state = process is inside a kernel I/O wait.
# The kernel only checks signals at instruction boundaries.
# Inside a syscall waiting for disk/NFS, that boundary never arrives.
# Even SIGKILL has no effect. Only the I/O completing (or reboot) helps.
DSTATE=$(ps aux | awk '$8 == "D" {print $2, $11}')
if [[ -z "$DSTATE" ]]; then
  ok_emit "No D-state processes"
else
  warn_emit "D-state (unkillable) processes:"
  emit "PID        COMMAND"
  emit "$DSTATE"
fi

sub "Top 15 processes by actual RAM (VmRSS)"
# VmSize = virtual address space (promises the kernel made, may not be backed)
# VmRSS  = resident set size (actual physical pages currently in RAM)
# The kernel's OOM killer uses a score from /proc/PID/oom_score to pick victims.
emit "$(printf '%-8s %-25s %10s %10s %8s %s\n' 'PID' 'NAME' 'RSS(MB)' 'VIRT(MB)' 'UID' 'OOM_SCORE')"
for statusfile in /proc/[0-9]*/status; do
  pid=$(echo "$statusfile" | grep -oP '\d+')
  awk -v pid="$pid" '
    /^Name:/   { name=$2 }
    /^VmRSS:/  { rss=int($2/1024) }
    /^VmSize:/ { vsz=int($2/1024) }
    /^Uid:/    { uid=$2 }
    END {
      if (rss > 0) printf "%s %s %d %d %s\n", pid, name, rss, vsz, uid
    }
  ' "$statusfile" 2>/dev/null
done | sort -t' ' -k3 -rn | head -15 | while read -r pid name rss vsz uid; do
  oom=$(cat "/proc/$pid/oom_score" 2>/dev/null || echo "?")
  printf '%-8s %-25s %10s %10s %8s %s\n' "$pid" "$name" "${rss}MB" "${vsz}MB" "$uid" "$oom"
done | tee -a "$TMPFILE"

sub "Open file descriptor counts (top 10)"
# Each FD is a slot in the kernel's open file table.
# Sockets are FDs. High FD count on a server can mean connection leak.
# ulimit -n is the per-process cap; hitting it returns EMFILE ("Too many open files").
emit "$(printf '%-8s %-25s %s\n' 'PID' 'NAME' 'FD_COUNT')"
for fddir in /proc/[0-9]*/fd; do
  pid=$(echo "$fddir" | grep -oP '\d+')
  name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
  count=$(ls "$fddir" 2>/dev/null | wc -l)
  printf '%s %s %s\n' "$pid" "$name" "$count"
done | sort -t' ' -k3 -rn | head -10 | while read -r pid name count; do
  printf '%-8s %-25s %s\n' "$pid" "$name" "$count"
done | tee -a "$TMPFILE"

sub "systemd failed units"
systemctl list-units --failed --no-legend 2>/dev/null | tee -a "$TMPFILE" || \
  emit "(systemctl not available)"

sub "Services listening on network (what is exposed)"
# ss replaces netstat. -t=TCP -l=listening -n=numeric -p=process
# Every listening port is an attack surface.
if command -v ss &>/dev/null; then
  ss -tlnp 2>/dev/null | tee -a "$TMPFILE"
else
  emit "(ss not available)"
fi

# ── SECTION 3: USERS & GROUPS ───────────────────────────────────────────────
section "USERS AND GROUPS"

sub "Accounts with UID 0 (all have unrestricted kernel access)"
# The kernel checks UID integer, not the string 'root'.
# Any UID-0 account has the same power as root regardless of name.
# Two UID-0 entries in /etc/passwd = backdoor.
UID0=$(awk -F: '$3 == 0 { print $1, $3, $7 }' /etc/passwd)
UID0_COUNT=$(echo "$UID0" | grep -c . || true)
if [[ $UID0_COUNT -gt 1 ]]; then
  warn_emit "Multiple UID-0 accounts found:"
  emit "$(printf '%-20s %s  %s\n' 'USERNAME' 'UID' 'SHELL')"
  emit "$UID0"
else
  ok_emit "Only one UID-0 account (root):"
  emit "$UID0"
fi

sub "Accounts with login shell (can log in)"
emit "$(printf '%-20s %-8s %-8s %s\n' 'USERNAME' 'UID' 'GID' 'SHELL')"
awk -F: '$7 !~ /nologin|false|sync|halt|shutdown/ { printf "%-20s %-8s %-8s %s\n", $1, $3, $4, $7 }' \
  /etc/passwd | tee -a "$TMPFILE"

sub "Accounts with empty password (no authentication required)"
# /etc/shadow field 2 is the password hash.
# Empty = no password needed. '!' or '*' = locked/disabled.
if [[ $EUID -eq 0 ]]; then
  EMPTY_PW=$(awk -F: '$2 == "" { print $1 }' /etc/shadow 2>/dev/null)
  if [[ -z "$EMPTY_PW" ]]; then
    ok_emit "No accounts with empty password"
  else
    warn_emit "Accounts with NO password:"
    emit "$EMPTY_PW"
  fi
else
  emit "(need root to read /etc/shadow)"
fi

sub "sudo privileges (who can become root)"
emit "--- /etc/sudoers (if readable) ---"
if [[ $EUID -eq 0 ]]; then
  cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | tee -a "$TMPFILE" || true
  emit ""
  emit "--- /etc/sudoers.d/ ---"
  ls /etc/sudoers.d/ 2>/dev/null | while read -r f; do
    emit "[$f]"
    grep -v '^#' "/etc/sudoers.d/$f" 2>/dev/null | grep -v '^$' | tee -a "$TMPFILE" || true
  done
else
  # Non-root: show what the current user can run
  sudo -l 2>/dev/null | tee -a "$TMPFILE" || emit "(sudo -l failed or not installed)"
fi

sub "Password aging policy (from /etc/shadow)"
# Columns: last_change:min_age:max_age:warn:inactive:expire
if [[ $EUID -eq 0 ]]; then
  emit "$(printf '%-20s %-12s %-12s %-12s %s\n' 'USER' 'LAST_CHANGE' 'MAX_AGE_DAYS' 'WARN_DAYS' 'EXPIRES')"
  while IFS=: read -r user pw last min max warn inactive expire _; do
    [[ "$pw" =~ ^[!*]?$ ]] && continue  # skip locked/no-password
    [[ -z "$user" ]] && continue
    last_human=$(date -d "1970-01-01 + $last days" '+%Y-%m-%d' 2>/dev/null || echo "$last")
    exp_human=$([ -n "$expire" ] && date -d "1970-01-01 + $expire days" '+%Y-%m-%d' 2>/dev/null || echo "never")
    printf '%-20s %-12s %-12s %-12s %s\n' "$user" "$last_human" "${max:-never}" "${warn:-?}" "$exp_human"
  done < /etc/shadow 2>/dev/null | tee -a "$TMPFILE" || true
else
  emit "(need root to read /etc/shadow)"
fi

sub "Recent logins (last 10)"
# /var/log/wtmp is the binary log backing the 'last' command.
# Gaps or unexpected entries (root logins, odd hours, unknown IPs) are findings.
last -n 10 2>/dev/null | tee -a "$TMPFILE" || emit "(last command unavailable)"

sub "Currently logged in users"
w 2>/dev/null | tee -a "$TMPFILE" || who | tee -a "$TMPFILE"

sub "Cron jobs (all users)"
# Unauthorised cron jobs are a persistence mechanism.
# They survive process kills and reboots.
emit "--- System crontab (/etc/crontab) ---"
cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' | tee -a "$TMPFILE" || true

emit "--- /etc/cron.d/ ---"
for f in /etc/cron.d/*; do
  [[ -f "$f" ]] || continue
  emit "[$f]"
  grep -v '^#' "$f" 2>/dev/null | grep -v '^$' | tee -a "$TMPFILE" || true
done

emit "--- Per-user crontabs ---"
for u in $(cut -f1 -d: /etc/passwd); do
  crontab -u "$u" -l 2>/dev/null | grep -v '^#' | grep -v '^$' | while IFS= read -r line; do
    emit "$u: $line"
  done || true
done

# ── SECTION 4: LOGS & AUDITING ──────────────────────────────────────────────
section "LOGS AND AUDITING"

sub "Journal disk usage"
journalctl --disk-usage 2>/dev/null | tee -a "$TMPFILE" || emit "(journalctl unavailable)"

sub "Kernel ring buffer: recent errors"
# dmesg = kernel's ring buffer. OOM kills, hardware errors, driver issues appear here.
# -T adds human-readable timestamps (requires kernel >= 3.17).
dmesg -T 2>/dev/null | grep -iE 'error|fail|oom|warn|crit' | tail -20 | tee -a "$TMPFILE" || \
  dmesg | grep -iE 'error|fail|oom|warn' | tail -20 | tee -a "$TMPFILE" || true

sub "Failed SSH login attempts (top 10 source IPs)"
# Parse auth.log: filter failed password lines, extract IP (field 11), count.
# grep returns exit 1 on no match; || true prevents set -e from killing the script.
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
  [[ -f "$f" ]] && AUTH_LOG="$f" && break
done

if [[ -n "$AUTH_LOG" ]]; then
  emit "Source: $AUTH_LOG"
  FAILED=$(grep 'Failed password' "$AUTH_LOG" 2>/dev/null \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn | head -10)
  if [[ -z "$FAILED" ]]; then
    ok_emit "No failed SSH password attempts found"
  else
    warn_emit "Top IPs by failed SSH attempt:"
    emit "$(printf '%8s  %s\n' 'COUNT' 'IP')"
    emit "$FAILED"
  fi
else
  emit "(auth log not found at /var/log/auth.log or /var/log/secure)"
fi

sub "Successful SSH logins (last 10)"
if [[ -n "$AUTH_LOG" ]]; then
  grep 'Accepted' "$AUTH_LOG" 2>/dev/null | tail -10 | tee -a "$TMPFILE" || \
    ok_emit "No accepted SSH logins in log"
fi

sub "systemd failed units"
systemctl list-units --failed --no-legend 2>/dev/null | tee -a "$TMPFILE" || true

sub "auditd status"
if command -v auditctl &>/dev/null; then
  sudo auditctl -s 2>/dev/null | tee -a "$TMPFILE" || emit "(auditctl requires root)"
  emit ""
  emit "Active audit rules:"
  sudo auditctl -l 2>/dev/null | tee -a "$TMPFILE" || emit "(auditctl requires root)"
else
  emit "(auditd not installed — install with: sudo apt install auditd)"
fi

sub "Recent authentication events (journalctl)"
journalctl _SYSTEMD_UNIT=ssh.service --since '24 hours ago' --no-pager -n 20 \
  2>/dev/null | tee -a "$TMPFILE" || \
  emit "(journalctl ssh query failed)"

sub "Log file sizes"
emit "$(printf '%-60s %s\n' 'FILE' 'SIZE')"
find /var/log -type f 2>/dev/null | sort | while read -r f; do
  size=$(du -h "$f" 2>/dev/null | cut -f1)
  printf '%-60s %s\n' "$f" "$size"
done | tee -a "$TMPFILE"

# ── SAVE REPORT ─────────────────────────────────────────────────────────────
section "REPORT SAVED"

if [[ -z "$OUT_FILE" ]]; then
  OUT_FILE="/tmp/audit-$(hostname)-$(date +%Y%m%d-%H%M%S).txt"
fi

# mv is a single rename() syscall — atomic on the same filesystem.
# Never produces a partial file, unlike writing directly to the destination.
mv "$TMPFILE" "$OUT_FILE"
trap - EXIT  # cancel the rm -f trap since we moved the file

emit "Report: $OUT_FILE"
echo ""
echo "Done. Report saved to: $OUT_FILE"
