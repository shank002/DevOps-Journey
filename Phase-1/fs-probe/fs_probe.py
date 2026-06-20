#!/usr/bin/env python3
"""
fs-probe: makes the Linux VFS layer visible.

Five probes, each targeting a different kernel mechanism:
  1. inode-map    -- show that filenames are dentries pointing to inodes
  2. fd-table     -- show every open file description in a process
  3. perm-walk    -- show how the kernel evaluates permission bits
  4. delete-open  -- show a file that exists after its name is gone
  5. hard-vs-soft -- show the structural difference between link types

Run:
  python3 fs_probe.py                  # all probes
  python3 fs_probe.py --probe inode-map
  python3 fs_probe.py --probe fd-table --pid 1
  python3 fs_probe.py --probe delete-open
  python3 fs_probe.py --probe perm-walk --path /etc/shadow
  python3 fs_probe.py --probe hard-vs-soft

Needs: Python 3.6+, no pip installs.
Some probes need sudo (reading /proc/<pid>/fd for other users).
"""

import os
import sys
import stat
import argparse
import subprocess
import struct
import time
import signal
import errno
from pathlib import Path


# ── colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def h1(text):  print(f"\n{BOLD}{CYAN}{'━'*60}{RESET}\n{BOLD}{CYAN}  {text}{RESET}\n{BOLD}{CYAN}{'━'*60}{RESET}")
def h2(text):  print(f"\n{BOLD}{YELLOW}  ▸ {text}{RESET}")
def ok(text):  print(f"  {GREEN}✔{RESET}  {text}")
def err(text): print(f"  {RED}✘{RESET}  {text}")
def dim(text): print(f"  {DIM}{text}{RESET}")
def row(label, value): print(f"  {BOLD}{label:<26}{RESET}{value}")


# ── probe 1: inode-map ────────────────────────────────────────────────────────
def probe_inode_map(path_arg: str):
    """
    Show that multiple filenames can share one inode (hard links),
    and that the inode — not the name — is the actual file.

    Kernel path: namei() resolves the path string → dentry → inode.
    The inode holds st_ino (unique per filesystem), link count (st_nlink),
    timestamps, size, and block pointers. The filename lives only in the
    directory file, not in the inode itself.
    """
    h1("PROBE 1 — inode-map: filenames vs inodes")

    base = Path(path_arg) if path_arg else Path("/tmp/fs-probe-lab")
    if not base.exists():
        err(f"{base} not found. Run setup/plant.sh first.")
        return

    h2("Walking directory tree — showing inode numbers")
    print(f"\n  {'INODE':>12}  {'NLINK':>5}  {'SIZE':>8}  {'TYPE':<8}  PATH")
    print(f"  {'─'*12}  {'─'*5}  {'─'*8}  {'─'*8}  {'─'*40}")

    inode_to_paths: dict[int, list[str]] = {}

    for root, dirs, files in os.walk(base):
        dirs.sort()
        for name in sorted(files):
            p = Path(root) / name
            try:
                st = p.lstat()
                ino = st.st_ino
                nlink = st.st_nlink
                size = st.st_size
                ftype = _filetype(st.st_mode)
                display = str(p.relative_to(base.parent))
                print(f"  {ino:>12}  {nlink:>5}  {size:>8}  {ftype:<8}  {display}")
                inode_to_paths.setdefault(ino, []).append(str(p))
            except OSError as e:
                err(f"  {p}: {e}")

    # Flag shared inodes (hard links)
    shared = {ino: paths for ino, paths in inode_to_paths.items() if len(paths) > 1}
    if shared:
        h2("Hard links found — these names point to the same inode")
        for ino, paths in shared.items():
            print(f"\n  inode {BOLD}{ino}{RESET} is referenced by {len(paths)} names:")
            for p in paths:
                print(f"    {GREEN}→{RESET} {p}")
        print()
        ok("The inode has one refcount (st_nlink). The kernel frees the inode")
        ok("only when st_nlink drops to 0 AND no process holds it open.")
    else:
        dim("No hard links found in this tree. Run setup/plant.sh to create them.")

    h2("Kernel mechanic summary")
    dim("open('/tmp/fs-probe-lab/hardlink-b') triggers:")
    dim("  1. path_lookupat() walks each component through the dentry cache")
    dim("  2. Every directory lookup calls inode->i_op->lookup()")
    dim("  3. The final component yields an inode object")
    dim("  4. The inode object is what gets opened — the name is discarded")
    dim("  5. Two names resolving to the same st_ino share one inode object")


# ── probe 2: fd-table ─────────────────────────────────────────────────────────
def probe_fd_table(pid: int):
    """
    Show the open file descriptor table of a process via /proc/<pid>/fd.

    Each entry in /proc/<pid>/fd/ is a symlink. The kernel creates these
    dynamically from the process's struct files_struct → fdtable.
    The symlink target tells you what the fd is backed by:
      - a regular path      → file
      - socket:[inode]      → socket (TCP/UDP/Unix)
      - pipe:[inode]        → anonymous pipe
      - anon_inode:[type]   → eventpoll, signalfd, timerfd, etc.
    """
    h1(f"PROBE 2 — fd-table: open file descriptors of PID {pid}")

    fd_dir = Path(f"/proc/{pid}/fd")
    fdinfo_dir = Path(f"/proc/{pid}/fdinfo")

    if not fd_dir.exists():
        err(f"PID {pid} not found or /proc/{pid}/fd is not accessible.")
        err("Try: sudo python3 fs_probe.py --probe fd-table --pid <pid>")
        return

    # Read process name
    try:
        comm = Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        comm = "?"

    h2(f"Process: {comm} (PID {pid})")
    print(f"\n  {'FD':>4}  {'FLAGS':>6}  {'POS':>12}  TARGET")
    print(f"  {'─'*4}  {'─'*6}  {'─'*12}  {'─'*50}")

    type_counts: dict[str, int] = {}

    for link in sorted(fd_dir.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 99999):
        fd_num = link.name
        try:
            target = os.readlink(link)
        except OSError:
            target = "(unreadable)"

        # Determine fd type label
        if target.startswith("socket:"):
            label = "socket"
        elif target.startswith("pipe:"):
            label = "pipe"
        elif target.startswith("anon_inode:"):
            label = target.split(":")[1]
        elif target == "(deleted)":
            label = "deleted"
        else:
            label = "file"
        type_counts[label] = type_counts.get(label, 0) + 1

        # Read fdinfo for flags and pos
        flags_str = "?"
        pos_str = "?"
        try:
            fdinfo = (fdinfo_dir / fd_num).read_text()
            for line in fdinfo.splitlines():
                if line.startswith("flags:"):
                    flags_str = line.split(":")[1].strip()
                elif line.startswith("pos:"):
                    pos_str = line.split(":")[1].strip()
        except OSError:
            pass

        # Colour by type
        if label == "socket":
            col = CYAN
        elif label == "pipe":
            col = YELLOW
        elif label in ("eventpoll", "signalfd", "timerfd"):
            col = GREEN
        elif label == "deleted":
            col = RED
        else:
            col = RESET

        print(f"  {fd_num:>4}  {flags_str:>6}  {pos_str:>12}  {col}{target}{RESET}")

    h2("fd type summary")
    for ftype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:>4}  {ftype}")

    h2("Kernel mechanic summary")
    dim("Every process has a struct files_struct with an fdtable[] array.")
    dim("fd 0/1/2 are stdin/stdout/stderr — inherited across fork().")
    dim("Each entry points to a struct file (the open file description).")
    dim("That struct file has: f_pos (seek offset), f_flags (O_RDONLY etc),")
    dim("f_count (shared across dup/fork), and f_inode → the inode on disk.")
    dim("/proc/<pid>/fd/ is the kernel exposing this table via the procfs VFS.")


# ── probe 3: perm-walk ────────────────────────────────────────────────────────
def probe_perm_walk(target_path: str):
    """
    Walk the permission evaluation logic the kernel runs on a file.

    The kernel runs inode_permission() which checks:
      1. If effective UID == 0  → bypass DAC entirely (root wins)
      2. If effective UID == st_uid  → apply owner bits
      3. Elif effective GID (or any supplementary GID) == st_gid  → apply group bits
      4. Else → apply other bits

    This is DAC (Discretionary Access Control). SELinux/AppArmor layer on top.
    SUID/SGID change the effective UID/GID during exec, not during open().
    """
    h1("PROBE 3 — perm-walk: permission evaluation")

    path = Path(target_path)
    if not path.exists() and not path.is_symlink():
        err(f"Path not found: {target_path}")
        return

    st = path.lstat()
    mode = st.st_mode

    my_uid  = os.getuid()
    my_euid = os.geteuid()
    my_gid  = os.getgid()
    my_egid = os.getegid()

    # Get all supplementary groups
    try:
        supp_groups = os.getgroups()
    except OSError:
        supp_groups = []
    all_gids = set([my_egid] + supp_groups)

    h2(f"File: {path}")
    row("Inode",        f"{st.st_ino}")
    row("Owner UID",    f"{st.st_uid}  ({_uid_name(st.st_uid)})")
    row("Owner GID",    f"{st.st_gid}  ({_gid_name(st.st_gid)})")
    row("Raw mode",     f"{oct(mode)}  ({stat.filemode(mode)})")
    row("File type",    _filetype(mode))

    h2("Special bits")
    suid = bool(mode & stat.S_ISUID)
    sgid = bool(mode & stat.S_ISGID)
    sticky = bool(mode & stat.S_ISVTX)
    row("SUID set",   f"{GREEN}yes — exec runs as UID {st.st_uid} ({_uid_name(st.st_uid)}){RESET}" if suid else "no")
    row("SGID set",   f"{YELLOW}yes — exec runs as GID {st.st_gid} ({_gid_name(st.st_gid)}){RESET}" if sgid else "no")
    row("Sticky bit", f"{CYAN}yes — only owner can delete in this dir{RESET}" if sticky else "no")

    h2(f"Your process credentials")
    row("Real UID / EUID",  f"{my_uid} / {my_euid}  ({_uid_name(my_euid)})")
    row("Real GID / EGID",  f"{my_gid} / {my_egid}  ({_gid_name(my_egid)})")
    row("Supplementary GIDs", ", ".join(str(g) for g in sorted(all_gids)))

    h2("DAC evaluation (as the kernel does it)")

    def _perm_bits(mode, shift):
        """Extract r/w/x bits at given shift (6=owner, 3=group, 0=other)."""
        return ((mode >> shift) & 0b111)

    def _fmt_bits(bits):
        return ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")

    owner_bits = _perm_bits(mode, 6)
    group_bits = _perm_bits(mode, 3)
    other_bits = _perm_bits(mode, 0)

    if my_euid == 0:
        verdict_r = True; verdict_w = True
        verdict_x = bool(owner_bits & 1 or group_bits & 1 or other_bits & 1)
        rule_used = "root bypass (EUID 0)"
        colour = GREEN
    elif my_euid == st.st_uid:
        bits = owner_bits
        verdict_r = bool(bits & 4); verdict_w = bool(bits & 2); verdict_x = bool(bits & 1)
        rule_used = f"owner match (EUID {my_euid} == st_uid {st.st_uid})"
        colour = CYAN
    elif st.st_gid in all_gids:
        bits = group_bits
        verdict_r = bool(bits & 4); verdict_w = bool(bits & 2); verdict_x = bool(bits & 1)
        rule_used = f"group match (GID {st.st_gid} in your groups)"
        colour = YELLOW
    else:
        bits = other_bits
        verdict_r = bool(bits & 4); verdict_w = bool(bits & 2); verdict_x = bool(bits & 1)
        rule_used = "other (no uid/gid match)"
        colour = RED

    print(f"\n  Rule applied: {colour}{rule_used}{RESET}\n")
    print(f"  {'PERM':<6}  {'BITS (owner/group/other)':<28}  {'YOUR ACCESS'}")
    print(f"  {'─'*6}  {'─'*28}  {'─'*20}")
    print(f"  {'read':<6}  {_fmt_bits(owner_bits)}/{_fmt_bits(group_bits)}/{_fmt_bits(other_bits)}{'':>18}  {_verdict(verdict_r)}")
    print(f"  {'write':<6}  {'':>28}  {_verdict(verdict_w)}")
    print(f"  {'exec':<6}  {'':>28}  {_verdict(verdict_x)}")

    # Verify against actual OS check
    h2("Verification against actual access(2) syscall")
    for mode_flag, label in [(os.R_OK, "R_OK"), (os.W_OK, "W_OK"), (os.X_OK, "X_OK")]:
        try:
            accessible = os.access(str(path), mode_flag)
        except OSError:
            accessible = False
        status = f"{GREEN}granted{RESET}" if accessible else f"{RED}denied{RESET}"
        print(f"  access({label}): {status}")

    h2("Kernel mechanic summary")
    dim("inode_permission() in fs/namei.c is the DAC check.")
    dim("It runs BEFORE any filesystem-specific permission checks.")
    dim("CAP_DAC_OVERRIDE (part of full root) bypasses the check entirely.")
    dim("SUID only matters at execve() — not at open(). It changes the")
    dim("credential struct of the new process, not the current one.")

def _verdict(v): return f"{GREEN}granted{RESET}" if v else f"{RED}denied{RESET}"


# ── probe 4: delete-open ──────────────────────────────────────────────────────
def probe_delete_open():
    """
    Create a file, open it, delete the name, show the file still exists.

    This is the inode reference count model:
      - open() increments i_count (in-memory ref) and allocates an fd
      - unlink() decrements i_nlink (on-disk ref / dentry ref)
      - The kernel calls iput() which only frees inode blocks when
        BOTH i_nlink == 0 AND i_count == 0

    You can see this in /proc/<pid>/fd/<n> → "(deleted)"
    and in /proc/<pid>/fdinfo/<n> for the file position.

    This is also how log rotation works: logrotate renames/unlinks the
    old log, but the writing daemon still holds its fd open against
    the old inode — until the daemon is signalled to reopen.
    """
    h1("PROBE 4 — delete-open: the inode reference count model")

    tmpfile = Path("/tmp/fs-probe-deleteme")

    h2("Step 1: create and open the file")
    tmpfile.write_text("I exist in the kernel, even without a name.\n" * 100)
    st_before = tmpfile.stat()
    ok(f"Created {tmpfile}  (inode {st_before.st_ino}, size {st_before.st_size} bytes)")

    # Open it — keep the fd alive
    fd = os.open(str(tmpfile), os.O_RDONLY)
    ok(f"Opened fd={fd} in this process (PID {os.getpid()})")

    h2("Step 2: unlink the name")
    os.unlink(str(tmpfile))
    ok(f"Unlinked {tmpfile} — the dentry is gone, directory entry removed")
    ok(f"But our fd={fd} still points to inode {st_before.st_ino}")

    h2("Step 3: verify the file is gone by name but alive by fd")
    name_exists = tmpfile.exists()
    print(f"\n  Path exists?          {RED}No{RESET}" if not name_exists else f"  Path exists?  {GREEN}Yes{RESET}")

    # Can we still read through the fd?
    try:
        data = os.read(fd, 40)
        ok(f"Read {len(data)} bytes through fd={fd}: {data[:40]!r}")
    except OSError as e:
        err(f"Read failed: {e}")

    h2("Step 4: check /proc/self/fd to see the kernel's view")
    fd_link = Path(f"/proc/self/fd/{fd}")
    try:
        target = os.readlink(fd_link)
        col = RED if "(deleted)" in target else GREEN
        print(f"\n  /proc/self/fd/{fd}  →  {col}{target}{RESET}")
    except OSError as e:
        err(f"Could not read /proc symlink: {e}")

    h2("Step 5: get inode number from /proc/self/fdinfo")
    fdinfo_path = Path(f"/proc/self/fdinfo/{fd}")
    try:
        fdinfo = fdinfo_path.read_text()
        for line in fdinfo.splitlines():
            print(f"  {DIM}{line}{RESET}")
    except OSError as e:
        err(f"fdinfo unreadable: {e}")

    h2("Step 6: write new data to verify the inode is still live")
    # Re-open for writing before we close the read fd
    write_path = Path("/tmp/fs-probe-deleteme")   # same name — new inode
    write_path.write_text("new file, new inode\n")
    st_new = write_path.stat()
    print(f"\n  New file inode:   {st_new.st_ino}")
    print(f"  Old (deleted) fd: still pointing to inode {st_before.st_ino}")
    print(f"  Same inode?       {'yes (unexpected)' if st_new.st_ino == st_before.st_ino else 'no — confirmed separate'}")
    write_path.unlink()

    h2("Step 7: close the fd — now the kernel can free the inode")
    os.close(fd)
    ok(f"fd={fd} closed. i_count drops to 0. Kernel can now free inode {st_before.st_ino}.")
    ok("This is what 'lsof | grep deleted' finds: held-open deleted inodes.")

    h2("Kernel mechanic summary")
    dim("unlink(2) calls vfs_unlink() → dentry_unlink() → drops i_nlink.")
    dim("close(2) calls fput() → iput() → if i_count==0 && i_nlink==0 → evict_inode().")
    dim("Until both conditions hold, the inode blocks stay on disk / in page cache.")
    dim("Disk space is NOT reclaimed until the last fd closes.")
    dim("'df' shows space used; 'lsof +L1' shows deleted-but-held inodes consuming it.")


# ── probe 5: hard-vs-soft ─────────────────────────────────────────────────────
def probe_hard_vs_soft():
    """
    Show the structural difference between hard links and symlinks.

    Hard link: a new dentry pointing to the same inode.
      - Cannot cross filesystem boundaries (inode numbers are per-fs)
      - Cannot link directories (would break the DAG invariant of the tree)
      - No 'link type' concept — the inode doesn't know which name is 'real'

    Symlink: a special inode whose data IS the target path string.
      - Can cross filesystems
      - Can link directories
      - Can dangle (target gone → ENOENT on dereference)
      - Stored as a tiny inode (usually in inode itself if ≤60 chars — fast symlink)
    """
    h1("PROBE 5 — hard-vs-soft: link types at the inode level")

    base = Path("/tmp/fs-probe-links")
    base.mkdir(exist_ok=True)

    original = base / "original.txt"
    hardlink = base / "hardlink.txt"
    softlink = base / "softlink.txt"

    original.write_text("I am the original file\n")

    # Create hard link
    if hardlink.exists(): hardlink.unlink()
    os.link(str(original), str(hardlink))

    # Create symlink
    if softlink.exists() or softlink.is_symlink(): softlink.unlink()
    os.symlink(str(original), str(softlink))

    h2("stat() comparison — notice inode numbers")
    st_orig = original.stat()
    st_hard = hardlink.stat()
    st_soft = softlink.lstat()      # lstat: don't follow symlink
    st_soft_followed = softlink.stat()  # stat: follow it

    print(f"\n  {'NAME':<20}  {'INODE':>12}  {'NLINK':>6}  {'SIZE':>8}  TYPE")
    print(f"  {'─'*20}  {'─'*12}  {'─'*6}  {'─'*8}  {'─'*20}")

    for name, st, note in [
        ("original.txt",           st_orig,          ""),
        ("hardlink.txt",           st_hard,          "← same inode as original"),
        ("softlink.txt (lstat)",   st_soft,          "← symlink inode itself"),
        ("softlink.txt (stat)",    st_soft_followed, "← followed to target"),
    ]:
        ft = _filetype(st.st_mode)
        same = f"  {GREEN}{note}{RESET}" if note else ""
        print(f"  {name:<20}  {st.st_ino:>12}  {st.st_nlink:>6}  {st.st_size:>8}  {ft}{same}")

    h2("Key observations")
    if st_orig.st_ino == st_hard.st_ino:
        ok(f"original and hardlink share inode {st_orig.st_ino} — they ARE the same file")
    if st_soft.st_ino != st_orig.st_ino:
        ok(f"softlink has its OWN inode ({st_soft.st_ino}) — its data is the path string")
    ok(f"softlink inode size = {st_soft.st_size} bytes = len('{original}') = {len(str(original))}")

    h2("Symlink target (what the symlink inode stores as data)")
    target = os.readlink(str(softlink))
    print(f"\n  readlink({softlink.name}) → {CYAN}{target}{RESET}")
    dim("If this path goes away, the symlink dangling — kernel returns ENOENT")
    dim("on the next dereference attempt.")

    h2("Demonstrate dangling symlink")
    dangling = base / "dangling.txt"
    gone_target = base / "will-be-deleted.txt"
    gone_target.write_text("temporary")
    if dangling.is_symlink(): dangling.unlink()
    os.symlink(str(gone_target), str(dangling))
    gone_target.unlink()

    try:
        dangling.read_text()
        err("Expected ENOENT but file was readable — something unexpected happened")
    except FileNotFoundError:
        ok(f"dangling.txt → {os.readlink(str(dangling))} → ENOENT (target gone)")

    try:
        dangling_st = dangling.lstat()
        ok(f"lstat(dangling.txt) still works — symlink inode {dangling_st.st_ino} exists")
    except OSError as e:
        err(f"lstat failed: {e}")

    h2("Why hard links can't cross filesystems")
    dim("Inode numbers are meaningful only within one filesystem.")
    dim("A hard link on ext4 inode 12345 has no meaning on a tmpfs.")
    dim("The VFS would have no way to verify the target exists or is consistent.")
    dim("Symlinks store a path string — they work across filesystems because")
    dim("the path is re-resolved at dereference time through the full VFS.")

    h2("Kernel mechanic summary")
    dim("link(2)    → vfs_link() → d_instantiate() — new dentry, same inode object")
    dim("symlink(2) → vfs_symlink() → creates new inode, writes path as file data")
    dim("open(symlink) → follow_link() → re-runs path resolution on the stored string")
    dim("lstat(2) stops at the symlink inode; stat(2) follows it.")

    # Cleanup
    for p in [hardlink, softlink, dangling, original]:
        try: p.unlink()
        except OSError: pass
    try: base.rmdir()
    except OSError: pass


# ── utilities ─────────────────────────────────────────────────────────────────
def _filetype(mode):
    if stat.S_ISREG(mode):  return "file"
    if stat.S_ISDIR(mode):  return "dir"
    if stat.S_ISLNK(mode):  return "symlink"
    if stat.S_ISCHR(mode):  return "char-dev"
    if stat.S_ISBLK(mode):  return "block-dev"
    if stat.S_ISFIFO(mode): return "pipe/fifo"
    if stat.S_ISSOCK(mode): return "socket"
    return "unknown"

def _uid_name(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return "?"

def _gid_name(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (KeyError, ImportError):
        return "?"


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="fs-probe: make the Linux VFS layer visible",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Probes:
  inode-map    filenames are dentries; inodes are the actual files
  fd-table     open file descriptions in a process's fdtable
  perm-walk    how the kernel evaluates r/w/x permission bits
  delete-open  a file that outlives its own name (inode refcount model)
  hard-vs-soft structural difference between hard links and symlinks
        """
    )
    parser.add_argument("--probe", choices=["inode-map","fd-table","perm-walk","delete-open","hard-vs-soft"],
                        help="run a specific probe only")
    parser.add_argument("--pid",  type=int, default=os.getpid(),
                        help="target PID for fd-table (default: this process)")
    parser.add_argument("--path", default="/etc/passwd",
                        help="target path for perm-walk (default: /etc/passwd)")
    parser.add_argument("--dir",  default="/tmp/fs-probe-lab",
                        help="base directory for inode-map (default: /tmp/fs-probe-lab)")
    args = parser.parse_args()

    probes = {
        "inode-map":   lambda: probe_inode_map(args.dir),
        "fd-table":    lambda: probe_fd_table(args.pid),
        "perm-walk":   lambda: probe_perm_walk(args.path),
        "delete-open": probe_delete_open,
        "hard-vs-soft": probe_hard_vs_soft,
    }

    if args.probe:
        probes[args.probe]()
    else:
        for name, fn in probes.items():
            try:
                fn()
            except Exception as e:
                err(f"Probe '{name}' crashed: {e}")
                import traceback; traceback.print_exc()

    print(f"\n{DIM}{'─'*60}{RESET}\n")


if __name__ == "__main__":
    main()
