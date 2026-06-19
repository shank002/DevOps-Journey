#!/usr/bin/env python3
"""
proc-inspector: reads /proc directly to show process internals.

No external dependencies. Python 3.8+ only.

Usage:
  python3 inspect.py                  # table of all processes
  python3 inspect.py --pid 1          # deep-dive a single PID
  python3 inspect.py --watch          # refresh table every 2s
  python3 inspect.py --watch --pid 1  # watch a single PID
  python3 inspect.py --zombies        # list zombie processes only
  python3 inspect.py --top 20         # show top N by RSS
  sudo python3 inspect.py             # sudo gives access to other users' /proc entries
"""

import os
import sys
import time
import argparse
import signal
import shutil


# ── Kernel constants ─────────────────────────────────────────────────────────

# Process state codes from kernel source: fs/proc/array.c
# Each maps to the TASK_* constants in include/linux/sched.h
STATES = {
    'R': 'Running          ',
    'S': 'Sleeping         ',
    'D': 'Disk wait (UNKILLABLE)',
    'Z': 'Zombie           ',
    'T': 'Stopped          ',
    'I': 'Idle kernel thread',
    't': 'Traced/stopped   ',
    'X': 'Dead             ',
}

# Signal numbers -> names (standard POSIX + Linux extensions)
# These correspond to bit positions in the SigCgt bitmask in /proc/PID/status.
# Bit N-1 set means signal N has a registered handler in userspace.
SIGNALS = {
    1:  'SIGHUP',   2:  'SIGINT',   3:  'SIGQUIT',  4:  'SIGILL',
    5:  'SIGTRAP',  6:  'SIGABRT',  7:  'SIGBUS',   8:  'SIGFPE',
    9:  'SIGKILL',  10: 'SIGUSR1',  11: 'SIGSEGV',  12: 'SIGUSR2',
    13: 'SIGPIPE',  14: 'SIGALRM',  15: 'SIGTERM',  17: 'SIGCHLD',
    18: 'SIGCONT',  19: 'SIGSTOP',  20: 'SIGTSTP',
}

# Memory map region types — inferred from pathname in /proc/PID/maps
# Format per line: addr_start-addr_end perms offset dev inode [pathname]
MAP_TYPES = {
    '[heap]':  'HEAP   ',
    '[stack]': 'STACK  ',
    '[vdso]':  'VDSO   ',   # virtual dynamic shared object (kernel-mapped)
    '[vsyscall]': 'VSYSCALL',
    '.so':     'LIB    ',   # shared library
    '':        'ANON   ',   # anonymous mapping (no name)
}


# ── /proc readers ────────────────────────────────────────────────────────────

def read_status(pid: int) -> dict | None:
    """
    Parse /proc/PID/status into a dict.

    This file is a text rendering of the kernel's task_struct — the actual
    C struct the scheduler operates on. Every field here is a real kernel value,
    not an approximation.

    Key fields:
      Name:    process name (comm), truncated to 15 chars by kernel
      State:   single letter + description (R/S/D/Z/T/I)
      Pid:     process ID
      PPid:    parent process ID
      Uid:     real UID, effective UID, saved UID, filesystem UID
      Gid:     same for group
      Threads: number of threads in this thread group
      VmSize:  total virtual address space size (promises made by kernel)
      VmRSS:   resident set size (actual physical pages currently in RAM)
      VmPeak:  peak virtual memory usage
      VmData:  size of data segment
      VmStk:   size of stack
      VmExe:   size of text (code) segment
      SigCgt:  bitmask of caught signals (has a handler registered)
      SigBlk:  bitmask of blocked signals
      SigIgn:  bitmask of ignored signals
    """
    path = f'/proc/{pid}/status'
    fields: dict = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                key, _, val = line.partition(':')
                fields[key.strip()] = val.strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    return fields


def read_maps(pid: int) -> list[dict]:
    """
    Parse /proc/PID/maps — the process's virtual memory layout.

    Each line represents one contiguous region of virtual address space.
    Format: start-end perms offset dev inode [pathname]

    perms: r=read w=write x=execute p=private s=shared

    This is how the OS loader arranges a process in memory:
    - Text segment (r-xp): the executable code, read-only + executable
    - Data segment (rw-p): global variables, BSS
    - Heap (rw-p [heap]): malloc'd memory, grows upward
    - Stack (rw-p [stack]): local variables, grows downward
    - Shared libs (.so): mapped from disk into address space
    - vdso (r-xp [vdso]): kernel-provided code in userspace (avoids syscall overhead)
    """
    path = f'/proc/{pid}/maps'
    regions = []
    try:
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split(None, 5)
                if len(parts) < 5:
                    continue
                addr_range, perms, offset, dev, inode = parts[:5]
                pathname = parts[5] if len(parts) > 5 else ''
                start, _, end = addr_range.partition('-')
                size_bytes = int(end, 16) - int(start, 16)
                regions.append({
                    'addr':  addr_range,
                    'perms': perms,
                    'size':  size_bytes,
                    'path':  pathname.strip(),
                })
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return regions


def count_fds(pid: int) -> int:
    """
    Count open file descriptors by listing /proc/PID/fd/.

    Each entry in /proc/PID/fd/ is a symlink to the actual resource:
      0 -> /dev/pts/0        (stdin — a terminal)
      1 -> /dev/pts/0        (stdout — same terminal)
      2 -> /dev/pts/0        (stderr — same terminal)
      3 -> /etc/passwd       (a regular file)
      4 -> socket:[12345]    (a TCP/UDP socket)
      5 -> pipe:[67890]      (a pipe between two processes)

    When FD count approaches `ulimit -n` (check: cat /proc/PID/limits),
    the next open()/accept()/socket() call returns EMFILE: "Too many open files".
    This is a common failure mode in servers that don't close connections.
    """
    try:
        return len(os.listdir(f'/proc/{pid}/fd'))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return -1


def read_fd_list(pid: int) -> list[str]:
    """Read actual FD targets for a specific process."""
    fds = []
    fd_dir = f'/proc/{pid}/fd'
    try:
        for entry in sorted(os.listdir(fd_dir), key=lambda x: int(x) if x.isdigit() else 999):
            fd_path = os.path.join(fd_dir, entry)
            try:
                target = os.readlink(fd_path)
                fds.append(f'  fd {entry:>4}  →  {target}')
            except (FileNotFoundError, PermissionError):
                fds.append(f'  fd {entry:>4}  →  (unreadable)')
    except (FileNotFoundError, PermissionError):
        fds.append('  (not accessible — try sudo)')
    return fds


def read_cgroup(pid: int) -> str:
    """
    Read cgroup membership from /proc/PID/cgroup.

    Format: hierarchy_id:controllers:path
    The 'path' field reveals the process's resource container:
      /                           → top-level (no cgroup, or root cgroup)
      /system.slice/ssh.service   → systemd-managed service
      /docker/<container_id>      → Docker container
      /user.slice/user-1000.slice → user session

    cgroups are the kernel mechanism Docker and Kubernetes use for resource
    isolation. The cgroup path is how you tell "is this process inside a container?"
    without any container tooling.
    """
    try:
        with open(f'/proc/{pid}/cgroup', 'r') as f:
            for line in f:
                parts = line.strip().split(':', 2)
                if len(parts) == 3:
                    path = parts[2]
                    if path != '/':
                        return path
            return '/'
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return '(unreadable)'


def decode_sigcgt(hex_mask: str) -> list[str]:
    """
    Decode the SigCgt bitmask from /proc/PID/status.

    SigCgt is a 64-bit hex number. Bit N-1 being set means signal N
    has a userspace handler registered (via sigaction(2)).

    SIGKILL (9) and SIGSTOP (19) can NEVER appear here — the kernel
    does not allow them to be caught, blocked, or ignored. They are
    handled directly by the kernel scheduler, not delivered to userspace.

    A process with SIGTERM (15) caught handles shutdown gracefully.
    A process with SIGTERM NOT caught uses the kernel default: terminate immediately.
    This matters for containers: if PID 1 doesn't catch SIGTERM, docker stop
    kills it after a 10-second timeout with SIGKILL.
    """
    try:
        mask = int(hex_mask, 16)
    except ValueError:
        return ['(parse error)']

    caught = []
    for signum, name in sorted(SIGNALS.items()):
        if signum in (9, 19):  # can never be caught
            continue
        if mask & (1 << (signum - 1)):
            caught.append(name)
    return caught if caught else ['(none — all signals use kernel defaults)']


def read_ulimits(pid: int) -> dict:
    """
    Read resource limits from /proc/PID/limits.

    These are the ulimit values for this specific process.
    The 'open files' limit is critical for servers — hitting it returns EMFILE.
    """
    limits = {}
    try:
        with open(f'/proc/{pid}/limits', 'r') as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    # "Max open files" spans two words — handle it
                    key = ' '.join(parts[:-3]).strip()
                    soft = parts[-3]
                    hard = parts[-2]
                    limits[key] = {'soft': soft, 'hard': hard}
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return limits


def read_cmdline(pid: int) -> str:
    """Read the full command line from /proc/PID/cmdline (null-byte separated)."""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            raw = f.read()
        return raw.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return '(unreadable)'


def all_pids() -> list[int]:
    """List all numeric entries in /proc/ — each is a running process."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except PermissionError:
        pass
    return sorted(pids)


# ── Data assembly ─────────────────────────────────────────────────────────────

def get_process_info(pid: int) -> dict | None:
    """Assemble a complete info dict for a single process."""
    status = read_status(pid)
    if status is None:
        return None

    state_code = status.get('State', '?')[0]

    vm_rss_kb  = int(status.get('VmRSS',  '0 kB').split()[0])
    vm_size_kb = int(status.get('VmSize', '0 kB').split()[0])
    # Overcommit = virtual space promised but not yet backed by physical pages.
    # When the kernel can no longer honour these promises, the OOM killer fires.
    overcommit_kb = max(0, vm_size_kb - vm_rss_kb)

    uid_fields = status.get('Uid', '? ? ? ?').split()
    real_uid   = uid_fields[0] if uid_fields else '?'
    eff_uid    = uid_fields[1] if len(uid_fields) > 1 else '?'

    sigcgt_hex = status.get('SigCgt', '0000000000000000')

    return {
        'pid':          pid,
        'name':         status.get('Name', '?'),
        'state_code':   state_code,
        'state_desc':   STATES.get(state_code, f'Unknown ({state_code})'),
        'ppid':         status.get('PPid', '?'),
        'real_uid':     real_uid,
        'eff_uid':      eff_uid,
        'threads':      status.get('Threads', '1'),
        'vm_rss_kb':    vm_rss_kb,
        'vm_size_kb':   vm_size_kb,
        'overcommit_kb': overcommit_kb,
        'vm_rss_mb':    vm_rss_kb // 1024,
        'vm_size_mb':   vm_size_kb // 1024,
        'fd_count':     count_fds(pid),
        'sigcgt_hex':   sigcgt_hex,
        'sigcgt':       decode_sigcgt(sigcgt_hex),
        'cgroup':       read_cgroup(pid),
        'oom_score':    _read_int(f'/proc/{pid}/oom_score'),
    }


def _read_int(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return -1


# ── Display ───────────────────────────────────────────────────────────────────

TERM_WIDTH = shutil.get_terminal_size((100, 40)).columns

def clear():
    print('\033[2J\033[H', end='')


def print_table(top_n: int = 30):
    """Print a table of all processes, sorted by RSS descending."""
    processes = []
    for pid in all_pids():
        info = get_process_info(pid)
        if info:
            processes.append(info)

    # Sort by RSS descending
    processes.sort(key=lambda x: x['vm_rss_kb'], reverse=True)

    header = (
        f"{'PID':>7}  {'NAME':<18} {'STATE':<10} {'RSS':>7} {'VIRT':>7} "
        f"{'FDs':>5} {'UID':>5} {'OOM':>5}  CGROUP"
    )
    print(header)
    print('─' * min(TERM_WIDTH, 110))

    shown = 0
    zombies = 0
    dstate  = 0

    for p in processes:
        if shown >= top_n:
            break

        state_flag = ''
        if p['state_code'] == 'Z':
            zombies += 1
            state_flag = ' ⚠ ZOMBIE'
        elif p['state_code'] == 'D':
            dstate += 1
            state_flag = ' ⚠ D-STATE'

        cgroup_short = p['cgroup']
        if len(cgroup_short) > 30:
            cgroup_short = '...' + cgroup_short[-27:]

        print(
            f"{p['pid']:>7}  {p['name']:<18} {p['state_code']:<10} "
            f"{p['vm_rss_mb']:>5}MB {p['vm_size_mb']:>5}MB "
            f"{p['fd_count']:>5} {p['real_uid']:>5} {p['oom_score']:>5}  "
            f"{cgroup_short}{state_flag}"
        )
        shown += 1

    total = len(processes)
    print('─' * min(TERM_WIDTH, 110))
    print(f"Showing {shown} of {total} processes  |  "
          f"Zombies: {zombies}  |  D-state: {dstate}  |  "
          f"Sorted by RSS")
    if zombies > 0:
        print(f"  ⚠  {zombies} zombie(s) — use --zombies to list them")
    if dstate > 0:
        print(f"  ⚠  {dstate} D-state process(es) — these cannot be killed")


def print_detail(pid: int):
    """Deep-dive into a single process — all /proc fields explained."""
    info = get_process_info(pid)
    if info is None:
        print(f"PID {pid} not found or not accessible.")
        return

    cmdline = read_cmdline(pid)
    maps    = read_maps(pid)
    fds     = read_fd_list(pid)
    limits  = read_ulimits(pid)

    print(f"\n{'═'*60}")
    print(f"  PID {pid}: {info['name']}")
    print(f"{'═'*60}")

    # ── Identity
    print(f"\n── Identity")
    print(f"  Command line : {cmdline[:100]}")
    print(f"  Parent PID   : {info['ppid']}")
    print(f"  Real UID     : {info['real_uid']}")
    print(f"  Effective UID: {info['eff_uid']}")
    print(f"  Threads      : {info['threads']}")

    # ── State
    print(f"\n── Process State")
    print(f"  State code   : {info['state_code']}")
    print(f"  Description  : {info['state_desc']}")
    if info['state_code'] == 'Z':
        print("  ⚠  ZOMBIE: parent has not called wait(). PID slot held.")
        print("     Cannot be killed. Kill or fix the parent process.")
        print(f"     Parent PID: {info['ppid']}")
    elif info['state_code'] == 'D':
        print("  ⚠  D-STATE: inside uninterruptible kernel wait (I/O).")
        print("     SIGKILL has no effect. Kernel signal check never arrives.")
        print("     Only the underlying I/O completing (or reboot) can unstick this.")
    print(f"  OOM score    : {info['oom_score']}  (higher = more likely OOM-killed)")
    print(f"     (tune with: echo N | sudo tee /proc/{pid}/oom_score_adj)")

    # ── Memory
    print(f"\n── Memory  (from /proc/{pid}/status)")
    print(f"  VmRSS   : {info['vm_rss_mb']:>6} MB  ← actual physical RAM pages")
    print(f"  VmSize  : {info['vm_size_mb']:>6} MB  ← virtual space (kernel promises)")
    print(f"  Overcommit: {info['overcommit_kb']//1024:>5} MB  ← promised but not yet backed")
    print()
    print(f"  VmRSS is what the process actually costs right now.")
    print(f"  The {info['overcommit_kb']//1024}MB gap is overcommit — memory the kernel")
    print(f"  promised but hasn't had to provide yet. If RAM pressure grows,")
    print(f"  the OOM killer may choose this process (score: {info['oom_score']}).")

    # ── Memory map
    print(f"\n── Memory Map  (/proc/{pid}/maps) — {len(maps)} regions")
    if maps:
        print(f"  {'ADDRESS RANGE':<35} {'PERMS':<6} {'SIZE':>8}  TYPE / PATH")
        print(f"  {'─'*80}")
        for region in maps[:25]:
            size_str = _human_size(region['size'])
            path     = region['path']

            # classify region
            if path == '[heap]':
                kind = 'HEAP'
            elif path == '[stack]':
                kind = 'STACK'
            elif path == '[vdso]':
                kind = 'VDSO (kernel-mapped)'
            elif path == '[vsyscall]':
                kind = 'VSYSCALL'
            elif path.endswith('.so') or '.so.' in path:
                kind = f'LIB  {os.path.basename(path)}'
            elif path and not path.startswith('['):
                kind = f'FILE {os.path.basename(path)}'
            else:
                kind = 'ANON (malloc/mmap)'

            print(f"  {region['addr']:<35} {region['perms']:<6} {size_str:>8}  {kind}")
        if len(maps) > 25:
            print(f"  ... ({len(maps) - 25} more regions)")

    # ── File descriptors
    print(f"\n── File Descriptors  (/proc/{pid}/fd/) — {info['fd_count']} open")
    fd_limit = limits.get('Max open files', {}).get('soft', '?')
    print(f"  ulimit (soft): {fd_limit}")
    if info['fd_count'] != -1 and fd_limit not in ('?', 'unlimited'):
        try:
            pct = int(info['fd_count']) / int(fd_limit) * 100
            print(f"  Usage        : {pct:.1f}%")
            if pct > 80:
                print(f"  ⚠  HIGH FD usage — approaching limit. Check for leaks.")
        except (ValueError, ZeroDivisionError):
            pass

    for line in fds[:20]:
        print(line)
    if len(fds) > 20:
        print(f"  ... ({len(fds) - 20} more FDs)")

    # ── Signals
    print(f"\n── Signal Disposition  (SigCgt bitmask: {info['sigcgt_hex']})")
    print(f"  Caught signals (have userspace handlers):")
    for sig in info['sigcgt']:
        print(f"    {sig}")
    print()
    print(f"  SIGKILL and SIGSTOP are never in this list — they cannot be")
    print(f"  caught, blocked, or ignored by any process. The kernel handles")
    print(f"  them directly without delivering to userspace.")

    # ── Cgroup
    print(f"\n── cgroup  (/proc/{pid}/cgroup)")
    print(f"  Path: {info['cgroup']}")
    if '/docker/' in info['cgroup']:
        container_id = info['cgroup'].split('/docker/')[-1][:12]
        print(f"  → Inside Docker container: {container_id}")
    elif '/system.slice/' in info['cgroup']:
        svc = info['cgroup'].split('/system.slice/')[-1]
        print(f"  → systemd service: {svc}")
    elif '/user.slice/' in info['cgroup']:
        print(f"  → User session")
    elif info['cgroup'] == '/':
        print(f"  → Root cgroup (no specific resource constraints)")


def print_zombies():
    """List only zombie processes with their parent info."""
    found = False
    print(f"{'PID':>7}  {'NAME':<20}  {'PPID':>7}  PARENT NAME")
    print('─' * 60)
    for pid in all_pids():
        status = read_status(pid)
        if status and status.get('State', '')[0] == 'Z':
            found = True
            ppid = status.get('PPid', '?')
            pname = '?'
            if ppid.isdigit():
                pstatus = read_status(int(ppid))
                if pstatus:
                    pname = pstatus.get('Name', '?')
            print(f"{pid:>7}  {status.get('Name', '?'):<20}  {ppid:>7}  {pname}")
            print(f"         To fix: kill parent PID {ppid} (or fix it to call wait())")
    if not found:
        print("No zombie processes found.")


def _human_size(n_bytes: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n_bytes < 1024:
            return f'{n_bytes:.0f}{unit}'
        n_bytes //= 1024
    return f'{n_bytes:.0f}TB'


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Read /proc directly to inspect process internals.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--pid',     type=int, help='Deep-dive a specific PID')
    ap.add_argument('--watch',   action='store_true', help='Refresh every 2s (Ctrl+C to stop)')
    ap.add_argument('--zombies', action='store_true', help='List zombie processes only')
    ap.add_argument('--top',     type=int, default=30, help='Number of processes to show (default: 30)')
    args = ap.parse_args()

    # Ctrl+C should exit cleanly
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    if args.zombies:
        print_zombies()

    elif args.watch and args.pid:
        while True:
            clear()
            print(f"proc-inspector — watching PID {args.pid} (Ctrl+C to stop)")
            print(f"Updated: {time.strftime('%H:%M:%S')}\n")
            print_detail(args.pid)
            time.sleep(2)

    elif args.watch:
        while True:
            clear()
            print(f"proc-inspector — process table (Ctrl+C to stop)")
            print(f"Updated: {time.strftime('%H:%M:%S')}\n")
            print_table(top_n=args.top)
            time.sleep(2)

    elif args.pid:
        print_detail(args.pid)

    else:
        print_table(top_n=args.top)


if __name__ == '__main__':
    main()
