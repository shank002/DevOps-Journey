# linux-audit-snapshot

A Bash script that takes a point-in-time security snapshot of a Linux system.
Run it before and after introducing deliberate misconfigurations — the diff between
`pre` and `post` is where the learning happens.

Covers the four Linux Fundamentals areas:
- **Filesystem** — inodes, SUID/SGID binaries, world-writable files, deleted-but-open files
- **Processes** — zombies, D-state, memory (VmRSS vs VmSize), FD counts
- **Users & Groups** — UID-0 accounts, empty passwords, sudo policy, cron jobs
- **Logs & Auditing** — failed SSH IPs, kernel errors, auditd rules, journal size

---

## Project structure

```
linux-audit-snapshot/
  snapshot.sh                    # main script
  setup/
    break-things.sh              # introduce deliberate findings (VM only)
    cleanup.sh                   # undo everything break-things.sh did
  Linux-snapshot-pre/            # screenshots taken BEFORE break-things.sh
    pre-FileSystem.png
    pre-INFO.png
    pre-SGIDbins.png
    pre-SUIDbin.png
  Linux-Snapshot-post/           # screenshots taken AFTER break-things.sh
    post-INFO.png
    post-FileSystem.png
    post-SUID.png
    post-SDID.png
    post-Writables.png
    post-DeletedOpen-Files.png
    post-Process1.png
    post-Process2.png
    post-UsersGroups.png
```

The `pre/` and `post/` folders are the actual evidence — the script output before
and after misconfigurations were introduced. Every finding in `post/` has a kernel
explanation below.

---

## Quickstart

```bash
# 1. Take a VM snapshot first (VirtualBox: Machine > Take Snapshot)

# 2. Baseline — run before introducing any findings
sudo ./snapshot.sh --out baseline.txt

# 3. Introduce findings
sudo bash setup/break-things.sh

# 4. Run again — compare against baseline
sudo ./snapshot.sh --out findings.txt
diff baseline.txt findings.txt

# 5. Clean up
sudo bash setup/cleanup.sh
```

---

## Usage

```bash
sudo ./snapshot.sh                        # saves to /tmp/audit-<hostname>-<timestamp>.txt
sudo ./snapshot.sh --out ./report.txt     # specify output file
sudo ./snapshot.sh --quiet --out report.txt   # suppress stdout, write file only
```

Run with `sudo` for full coverage — shadow file, sudoers, auditd, cron jobs for all users.
Without sudo it still runs but skips root-only checks.

---

## What each screenshot shows

### `pre-INFO.png` / `post-INFO.png` — report header

The header line shows hostname, kernel version, and who the script is running as.
This matters because many checks below silently skip if you are not root.

```
linux-audit-snapshot
Generated : 2024-06-19 10:23:45 UTC
Hostname  : mainBase
Kernel    : 6.x.x
Running as: uid=0(root) gid=0(root) groups=0(root)
```

---

### `pre-FileSystem.png` / `post-FileSystem.png` — disk and inode usage

```bash
df -h    # block usage
df -i    # inode usage
```

**What's actually happening:**

A file in Linux is an inode — a kernel data structure holding permissions, ownership,
timestamps, and pointers to data blocks. A filename is just a directory entry (dentry)
that maps a name to an inode number. `df -h` measures data blocks. `df -i` measures
inodes — they are separate counters on the same filesystem.

**What the pre/post diff shows:**

The `post` run may show higher inode usage if `break-things.sh` created files.
The more important lesson: a disk can show free space in `df -h` but zero free inodes
in `df -i`, making it impossible to create new files. This hits log servers and build
caches that store millions of tiny files.

```bash
# Reproduce inode exhaustion on a tmpfs (safe, no real disk involved)
mkdir /tmp/inodetest
for i in $(seq 1 50000); do touch /tmp/inodetest/$i; done
df -i /tmp     # watch inode usage climb
rm -rf /tmp/inodetest
```

---

### `pre-SUIDbin.png` / `post-SUID.png` — SUID binaries

```bash
find / -xdev -perm -4000 -type f 2>/dev/null
```

**What's actually happening:**

The kernel checks **effective UID** (eUID), not real UID, on every syscall that
touches a file. When a binary has the SUID bit set, `exec()` flips the process's
eUID to the **file's owner** for the duration of execution.

```
Normal cat:    your eUID = 1000  →  kernel checks 1000 against file permissions
passwd (SUID): your eUID = 1000  →  exec() flips eUID to 0  →  kernel sees root
```

The `s` in `rwsr-xr-x` is the SUID bit:

```
-rwsr-xr-x 1 root root 64152 ... /usr/bin/passwd
     ^
     s = SUID set; executable by owner; runs as owner (root)
```

**What the pre/post diff shows:**

`pre` shows the system's legitimate SUID binaries (passwd, su, mount...).
`post` shows `/tmp/suspicious_cat` added by `break-things.sh` — same binary, same bit,
but in `/tmp` with no legitimate reason to be there. That's the finding.

```bash
# See the eUID flip in action
cp /bin/cat /tmp/mycat
chmod +s /tmp/mycat
ls -la /tmp/mycat           # shows rwsr-xr-x
/tmp/mycat /etc/shadow      # still fails — root owns shadow, but permissions say 640
                            # (SUID only helps if file owner has access)

# The dangerous version: a SUID bash
cp /bin/bash /tmp/mybash
chmod +s /tmp/mybash
/tmp/mybash -p              # -p = preserve effective UID
id                          # euid=0(root) — you have a root shell
```

**Check GTFOBins** (`https://gtfobins.github.io`) for every SUID binary you find —
it catalogues which ones can be leveraged for privilege escalation.

---

### `post-SDID.png` — SGID binaries

```bash
find / -xdev -perm -2000 -type f 2>/dev/null
```

**What's actually happening:**

SGID does the same thing as SUID but for group ID. The `s` appears in the group
execute position instead of owner execute:

```
-rwxr-sr-x 1 root shadow 72184 ... /usr/bin/chage
              ^
              s = SGID; runs as group 'shadow'
```

`chage` needs to read `/etc/shadow` (owned by root, group shadow, mode 640).
By running as group `shadow`, it can read shadow without being root.
Less dangerous than SUID to root, but still worth auditing.

---

### `post-Writables.png` — world-writable files

```bash
find / -xdev -type f -perm -0002 2>/dev/null
```

**What's actually happening:**

Unix permission bits are checked in order: owner → group → other.
`-0002` means the "other write" bit (bit 1 of the "other" triplet) is set —
any user on the system can write to this file.

```
-rwxrwxrwx  = 777 = world-writable + world-executable
-rw-rw-rw-  = 666 = world-writable
```

**Why it matters:**

World-writable + SUID path = instant escalation:
```bash
# If a SUID binary reads from a world-writable config file, you control its input.
# If a world-writable file is in root's PATH, you can replace a command root runs.
# If /etc/cron.d/ has a world-writable file, you control what root's cron executes.
```

**What the post screenshot shows:**

`break-things.sh` created `/tmp/world_writable_file.txt` with `chmod 777`.
The script finds it. In a real audit, findings outside `/tmp` and `/var/tmp`
(which are legitimately world-writable) are the ones that need investigation.

---

### `post-DeletedOpen-Files.png` — deleted files held open

```bash
lsof | grep '(deleted)'
```

**What's actually happening:**

`rm` calls `unlink()` — it removes the directory entry (the name-to-inode mapping).
The inode (and its data blocks) is freed only when **both** conditions are true:

1. Link count reaches 0 (no more filenames pointing to this inode)
2. Open file descriptor count reaches 0 (no process has it open)

`rm` satisfies condition 1. If a process still has the file open, condition 2
is not met — the inode stays alive and the data blocks stay occupied.

```
rm deleted_log.txt
  link count: 1 → 0  ✓  (dentry removed — file disappears from ls)
  open FDs  : 1       ✗  (process still writing to it)
  inode     : NOT freed
  disk space: NOT reclaimed
```

`df -h` still shows the space used. The file is invisible in `ls`. Only `lsof`
can find it because it reads `/proc/PID/fd/` directly — the kernel's FD table
still has an entry pointing to the inode.

**What the post screenshot shows:**

`break-things.sh` runs a Python process that:
1. Creates a temp file
2. Calls `os.unlink()` on it (the filename disappears)
3. Keeps the file descriptor open and holds it for 5 minutes

The script finds it via `lsof | grep '(deleted)'`.

**The production version of this bug:**

A log file gets rotated (`mv app.log app.log.1`). The application still has
a file descriptor to the original inode — it keeps writing there.
The rotated file gets no data. The new `app.log` is empty.
Fix: send `SIGHUP` to make the app reopen its log file, or use `copytruncate`
in logrotate config (copies then truncates in place, so the FD still works).

---

### `post-Process1.png` / `post-Process2.png` — processes

```bash
# Zombies
ps aux | awk '$8 == "Z"'

# D-state (unkillable)
ps aux | awk '$8 == "D"'

# Top consumers by actual RAM (VmRSS from /proc)
cat /proc/PID/status | grep VmRSS
```

**Zombies — what's actually happening:**

When a child process exits, it does not disappear. It becomes a zombie (state Z)
and stays in the process table until its parent calls `wait()` to collect its
exit code. A zombie holds:

- No CPU
- No memory
- **One PID slot** in the kernel's process table

If the parent never calls `wait()`, zombies accumulate. When the PID table fills
(`cat /proc/sys/kernel/pid_max` — typically 32768 or 4194304), no new processes
can be created. You cannot kill a zombie with `kill -9` — it has no running code
to receive the signal. Kill or fix the parent.

**D-state — what's actually happening:**

The kernel delivers signals at instruction boundaries — specifically, when returning
from a syscall or interrupt handler. A process waiting deep inside a kernel I/O
syscall (reading from a hung NFS mount, waiting for a slow disk) never reaches
that boundary. `SIGKILL` is queued but never delivered. Only the I/O completing
(or a reboot) can unstick it.

**What the post screenshots show:**

`break-things.sh` forks a child (Python), lets it exit, and has the parent sleep
without calling `wait()`. `post-Process1.png` and `post-Process2.png` show the
zombie appearing in `ps aux` output with state `Z`.

**VmRSS vs VmSize:**

```
VmSize = total virtual address space (what the kernel promised)
VmRSS  = resident set size (actual physical pages currently in RAM)
```

The gap is **overcommit** — the kernel bets that not all processes need all their
memory simultaneously. When that bet fails and RAM runs out, the OOM killer wakes up,
scores every process by `/proc/PID/oom_score`, and kills the highest scorer.

```bash
# See both values for any process
cat /proc/$$/status | grep -E 'VmRSS|VmSize'

# See OOM score
cat /proc/$$/oom_score
```

---

### `post-UsersGroups.png` — users and groups

```bash
# UID-0 accounts (all have unrestricted kernel access)
awk -F: '$3 == 0' /etc/passwd

# Accounts with empty password
sudo awk -F: '$2 == ""' /etc/shadow

# Recent logins
last -n 10

# Cron jobs for all users
for u in $(cut -f1 -d: /etc/passwd); do crontab -u "$u" -l 2>/dev/null; done
```

**What's actually happening:**

The kernel identifies users by **UID integer**, not username. Every permission check
is a comparison of integers:

```
open("/etc/shadow") → kernel checks: calling_process.eUID == file.UID (0)?
                      or: calling_process.eGID in file.groups?
                      or: other bits set?
```

The string "root" never appears in that check. A second account with UID 0 has
exactly the same kernel access as root regardless of its name. This is a classic
backdoor — first thing an incident responder checks:

```bash
awk -F: '$3==0 {print $1}' /etc/passwd
# Should return only: root
# Two entries = backdoor
```

**`/etc/shadow` fields:**

```
username:$6$salt$hash:last_change:min:max:warn:inactive:expire:
                ^                  ^         ^
                SHA-512 hash       last pw   max password age in days
```

- Empty field 2 (`username::...`) = no password required
- `!` or `*` prefix = account locked
- `$6$` = SHA-512, `$y$` = yescrypt (modern), `$1$` = MD5 (ancient, weak)

**Cron as a persistence mechanism:**

An attacker who gets temporary root access will often drop a cron job before
losing that access. Cron jobs survive process kills, logout, and reboots.
The audit script checks all of: `/etc/crontab`, `/etc/cron.d/`, and per-user
crontabs (`crontab -u USER -l`) for every user on the system.

---

## Why each check exists — the one-line version

| Screenshot | Command | Kernel mechanism |
|---|---|---|
| `pre/post-FileSystem` | `df -i` | Inodes are separate from blocks; both can be exhausted |
| `pre/post-SUIDbin` | `find -perm -4000` | SUID flips eUID to file owner on exec() |
| `post-SDID` | `find -perm -2000` | SGID flips eGID to file group on exec() |
| `post-Writables` | `find -perm -0002` | Other-write bit; any user can modify |
| `post-DeletedOpenFiles` | `lsof \| grep deleted` | rm = unlink(); inode freed only when FD count + link count = 0 |
| `post-Process1/2` | `ps aux \| awk '$8=="Z"'` | Zombie = exited child, parent never called wait() |
| `post-UsersGroups` | `awk -F: '$3==0' /etc/passwd` | Kernel checks UID integer, not username |

---

## Requirements

- Bash 4.x+
- Ubuntu 22.04 / Debian 12
- `lsof`: `sudo apt install lsof`
- `auditd` (optional): `sudo apt install auditd`
- Run with `sudo` for full coverage
