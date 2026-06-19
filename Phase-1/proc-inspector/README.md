# proc-inspector

A Python script that reads `/proc` directly to show process internals.

No external dependencies. stdlib only. Python 3.8+.

The goal is not the tool — it is understanding what `/proc` actually contains
and what each field means at the kernel level. Every value shown here is a live
number from the kernel's own data structures, not an approximation.

---

## Project structure

```
proc-inspector/
  inspect.py              # main script
  README.md
  screenshots/
    general-run.png       # default table view — all processes sorted by RSS
    systemd-check.png     # --pid deep dive on a systemd process
    zombie-check.png      # --zombies mode showing a deliberately created zombie
```

---

## Usage

```bash
# Default: process table, top 30 by RSS
python3 inspect.py

# Deep-dive a single process (everything /proc exposes about it)
python3 inspect.py --pid 1

# Live-updating table (refreshes every 2s, Ctrl+C to stop)
python3 inspect.py --watch

# Watch a single process live
python3 inspect.py --watch --pid $$

# List zombie processes only
python3 inspect.py --zombies

# Show top 50 instead of 30
python3 inspect.py --top 50

# sudo for full access to other users' /proc entries
sudo python3 inspect.py
```

---

## What each screenshot shows

### `general-run.png` — the process table

The default view. Reads `/proc/PID/status` for every numeric directory under
`/proc/` and builds a table sorted by RSS (actual RAM used), highest first.

```
    PID  NAME               STATE          RSS    VIRT   FDs   UID   OOM  CGROUP
────────────────────────────────────────────────────────────────────────────
    490  rclone-filestor    S             33MB  1910MB    11     0   672  /
    733  python3            R             12MB    17MB     4     0   668  ...
      1  systemd            S              4MB    17MB    15     0     0  /
```

**Columns and what they mean:**

**`RSS` (VmRSS)** — actual physical pages currently in RAM. This is what the
process *actually costs* right now. Read directly from `/proc/PID/status`:
```
VmRSS:   3456 kB
```

**`VIRT` (VmSize)** — total virtual address space. This is what the kernel
*promised* when the process called `malloc()` or `mmap()`. It is almost always
larger than RSS because of overcommit: the kernel makes promises it bets it
won't have to keep. When RAM pressure forces it to honour all promises at once,
the OOM killer fires.

**`FDs`** — number of open file descriptors, counted by listing `/proc/PID/fd/`.
Every file, socket, and pipe is an FD. When FD count hits the per-process limit
(`ulimit -n`), the next `open()` or `accept()` fails with `EMFILE: Too many open files`.
High FD count on a long-running server means check for connection or file leaks.

**`OOM`** — the kernel's OOM kill score from `/proc/PID/oom_score`. Higher = more
likely to be killed when the system runs out of memory. Range is 0–1000. The kernel
calculates it from RSS, runtime, and ownership. You can nudge it:
```bash
echo -500 | sudo tee /proc/<PID>/oom_score_adj   # protect a process
echo  500 | sudo tee /proc/<PID>/oom_score_adj   # make it a preferred victim
```

**`STATE`** — single letter from `/proc/PID/status`. The full set:

| Code | Meaning | Killable with SIGKILL? |
|------|---------|----------------------|
| `R`  | Running or on run queue | Yes |
| `S`  | Sleeping (interruptible) | Yes |
| `D`  | Waiting for I/O (uninterruptible) | **No** |
| `Z`  | Zombie — exited, parent hasn't called `wait()` | **No** |
| `T`  | Stopped by SIGSTOP or debugger | Yes (SIGCONT first) |
| `I`  | Idle kernel thread | — |

**`CGROUP`** — the cgroup path from `/proc/PID/cgroup`. This tells you which
resource container the process lives in:
```
/                                   → root cgroup, no constraints
/system.slice/ssh.service           → systemd-managed service
/docker/a1b2c3...                   → inside a Docker container
/user.slice/user-1000.slice/...     → user session
```
cgroups are the kernel primitive Docker and Kubernetes are built on. The cgroup
path is how you tell "is this inside a container?" without any container tooling.

---

### `systemd-check.png` — `--pid` deep dive

```bash
python3 inspect.py --pid 1
```

Reads every `/proc/1/` file and formats it into sections. What you see in the
screenshot:

**Identity block** — name, full command line (from `/proc/PID/cmdline`, null-byte
separated), parent PID, real UID, effective UID, thread count.

**Memory block** — the RSS vs VmSize split with the overcommit gap calculated:
```
VmRSS   :      5 MB  ← actual physical RAM pages
VmSize  :     18 MB  ← virtual space (kernel promises)
Overcommit:    13 MB  ← promised but not yet backed
```

**Memory map** — the first 25 regions from `/proc/PID/maps`. Each line is one
contiguous virtual address region:
```
ADDRESS RANGE                    PERMS     SIZE   TYPE
55f1a0000000-55f1a0001000        r-xp       4KB   FILE bash    ← executable code
55f1a0400000-55f1a0600000        rw-p       2MB   HEAP         ← malloc'd memory
7fff12345000-7fff12365000        rw-p     128KB   STACK        ← local variables
7ffff7fc1000-7ffff7fc3000        r-xp       8KB   VDSO         ← kernel-in-userspace
```

`perms` field: `r`=read `w`=write `x`=execute `p`=private (copy-on-write) `s`=shared.
A region with `x` but no `w` is code (text segment). A region with `w` but no `x`
is data. A region with both `w` and `x` is suspicious — it can be written to and
then executed, which is a common exploit technique.

**File descriptors** — lists every FD with its target by reading symlinks in
`/proc/PID/fd/`:
```
fd    0  →  /dev/pts/0           (stdin)
fd    1  →  /dev/pts/0           (stdout)
fd    2  →  /dev/pts/0           (stderr)
fd    3  →  socket:[12345]       (TCP connection)
fd    4  →  pipe:[67890]         (IPC pipe)
fd    5  →  /var/log/app.log     (log file)
```
FD 0, 1, 2 are always stdin/stdout/stderr — the kernel sets these up at process
creation. Everything above 2 is opened by the process itself. Sockets are FDs.
Pipes are FDs. The "everything is a file" abstraction means the same
`read()`/`write()`/`select()` syscalls work on all of them.

**Signal disposition** — decodes the `SigCgt` hex bitmask from `/proc/PID/status`.
Bit N−1 set means signal N has a registered userspace handler:
```
SigCgt bitmask: 0000000000000440
Caught signals:
  SIGBUS     (bit 6)
  SIGSEGV    (bit 10)
```
`SIGKILL` (9) and `SIGSTOP` (19) are never in this list. The kernel does not
allow any process to catch, block, or ignore them — they are handled by the
scheduler directly. This is why `kill -9` always terminates a *running* process.

**cgroup path** — shows where in the cgroup hierarchy this process sits, and
whether it is inside a Docker container or systemd service.

---

### `zombie-check.png` — `--zombies` mode

```bash
python3 inspect.py --zombies
```

Scans all PIDs, filters for state `Z`, and prints the zombie with its parent:

```
    PID  NAME                   PPID  PARENT NAME
────────────────────────────────────────────────────────────
   4821  python3               4800   python3
         To fix: kill parent PID 4800 (or fix it to call wait())
```

**What a zombie actually is:**

When a child process exits, the kernel does not immediately free its process
table entry. It transitions to state `Z` and waits for the parent to call
`wait()` or `waitpid()` to collect the exit code. Until the parent does that,
the entry stays — occupying one PID slot.

A zombie holds:
- No CPU time
- No memory
- **One row in the kernel's process table** (one PID slot)

If the parent never calls `wait()`, zombies accumulate. The PID table has a
finite size (`cat /proc/sys/kernel/pid_max`). When it fills, no new processes
can be created anywhere on the system — `fork()` returns `EAGAIN`.

**Why `kill -9` does nothing to a zombie:**

`SIGKILL` is delivered by the kernel to a running process. A zombie has no
running code — it has already exited. There is nothing to deliver the signal to.
The zombie disappears only when:
1. The parent calls `wait()` (normal cleanup)
2. The parent dies (kernel reparents zombie to PID 1, which calls `wait()`)

**How to create the zombie the screenshot shows:**

```bash
python3 -c "
import os, time, sys

pid = os.fork()
if pid == 0:
    # Child: exit immediately
    os._exit(0)
else:
    # Parent: never call wait() — child becomes zombie
    print(f'Parent PID={os.getpid()}, zombie child PID={pid}')
    sys.stdout.flush()
    time.sleep(60)    # hold open long enough to inspect
" &

# Now run the inspector
python3 inspect.py --zombies
```

**In production, zombies appear when:**
- A web server spawns worker processes and the master has a bug in its signal handler
- A container runs without a proper init process (PID 1) that reaps orphans
- A shell script forks background jobs and exits before they finish

This is why Docker's `--init` flag exists and why `tini` is used as a container
init — their only job is to call `wait()` on any orphaned child.

---

## What `/proc` actually is

`/proc` is not a real filesystem on disk. It is a virtual filesystem — the kernel
generates its contents on demand when you read from it. Every file under
`/proc/PID/` is the kernel exposing its own internal data structures as readable
text.

```
/proc/PID/status    → task_struct fields (scheduler's view of the process)
/proc/PID/maps      → vm_area_struct list (memory manager's view)
/proc/PID/fd/       → file descriptor table (VFS's view)
/proc/PID/cgroup    → cgroup membership (resource controller's view)
/proc/PID/limits    → rlimit table (per-process resource caps)
/proc/PID/cmdline   → argv[] from exec() (null-byte separated)
```

When you `cat /proc/1/status`, the kernel runs code that serialises its
`task_struct` for PID 1 into text and hands it back. No file was read from disk.
This means the values are always current — there is no caching or staleness.

This script reads all of those files directly, with no `ps`, no `top`, no
external tools — the same data those tools use, accessed at the source.

---

## Experiments to run

### Watch RSS grow in real time

```bash
# Terminal 1 — allocate memory slowly
python3 -c "
import time
data = []
for i in range(30):
    data.append(b'x' * 10_000_000)   # 10MB per iteration
    print(f'Allocated {(i+1)*10}MB total')
    time.sleep(2)
"

# Terminal 2 — watch it in proc-inspector
python3 inspect.py --watch --pid <PID>
# VmRSS climbs with each iteration
# VmSize jumps ahead immediately (overcommit promise)
# The gap between them is the overcommit
```

### FD inheritance across fork

```bash
# Open a custom FD in bash
exec 7</etc/passwd         # fd 7 now points to /etc/passwd

# Inspect your shell's FDs
python3 inspect.py --pid $$
# fd 7 → /etc/passwd should appear in the list

# Now close it
exec 7>&-
python3 inspect.py --pid $$
# fd 7 is gone
```

### See what systemd has open

```bash
python3 inspect.py --pid 1
# FD list shows every socket, pipe, and file systemd holds
# cgroup path shows it lives at the root cgroup (no constraints)
# SigCgt shows which signals systemd catches (SIGTERM, SIGHUP for reload, etc.)
```

---

## Requirements

- Python 3.8+
- Linux only — reads `/proc`, which does not exist on macOS or Windows
- `sudo` recommended — without it, `/proc/PID/` entries for other users' processes
  are not readable (PermissionError is caught silently, those PIDs are skipped)
