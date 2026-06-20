# fs-probe

A Python tool that makes the Linux VFS layer visible. Five probes, each targeting a different kernel mechanism in the filesystem stack.

This is part of a Phase 1 Linux Fundamentals portfolio — specifically the **Filesystem** sub-topic. No external dependencies. No frameworks. Just Python stdlib reading what the kernel exposes.

---

## What this is actually doing

When you call `open("file.txt")`, you're not interacting with a disk. You're going through the **VFS (Virtual File System)** — a kernel abstraction layer that sits between your process and whatever actual filesystem (ext4, tmpfs, btrfs) is underneath.

The VFS resolves your path string through the **dentry cache**, finds an **inode** (the actual file object, not the name), allocates a **struct file** in kernel memory, and hands your process back an integer — the file descriptor. Everything you think of as "a file" is built on top of that chain.

This project makes each step of that chain observable.

---

## Project structure

```
fs-probe/
├── fs_probe.py          # five probes — run this
├── setup/
│   ├── plant.sh         # builds a test directory tree for probe 1
│   └── cleanup.sh       # removes everything plant.sh created
└── README.md
```

---

## Probes

### Probe 1 — `inode-map`
**The kernel mechanic:** Filenames are directory entries (dentries). The inode is the actual file. Multiple names can map to one inode — hard links. The inode holds the refcount (`st_nlink`); the kernel only frees inode blocks when that count and the open-fd count both hit zero.

**What to look for in the output:** Three filenames (`hardlink-original.txt`, `hardlink-alias.txt`, `subdir/hardlink-third.txt`) all showing the same inode number. `st_nlink = 3` on each. The filename is not part of the inode — it lives only in the directory file.

```bash
bash setup/plant.sh
python3 fs_probe.py --probe inode-map
```

---

### Probe 2 — `fd-table`
**The kernel mechanic:** Every process has a `struct files_struct` with an `fdtable[]` array. `fd 0/1/2` are stdin/stdout/stderr, inherited across `fork()`. Each entry points to a `struct file` — the open file description — which holds the seek offset (`f_pos`), flags, and a pointer to the inode. `/proc/<pid>/fd/` is the kernel exposing this table via procfs.

**What to look for in the output:** The fd number, the flags byte from `/proc/<pid>/fdinfo/`, and the target — which reveals what the fd is backed by: a path, `socket:[inode]`, `pipe:[inode]`, or `anon_inode:[type]`.

```bash
# Inspect this process
python3 fs_probe.py --probe fd-table

# Inspect another process (needs sudo for other users' processes)
python3 fs_probe.py --probe fd-table --pid 1

# Interesting target: a process with open sockets and pipes
python3 fs_probe.py --probe fd-table --pid $(pgrep sshd | head -1)
```

---

### Probe 3 — `perm-walk`
**The kernel mechanic:** `inode_permission()` in `fs/namei.c` runs DAC (Discretionary Access Control) checks in strict order: if EUID == 0 → bypass entirely; elif EUID == `st_uid` → apply owner bits; elif EGID (or any supplementary GID) == `st_gid` → apply group bits; else → apply other bits. The kernel stops at the first match. SUID/SGID only matter at `execve()` — they change the credential struct of the new process, not the calling one.

**What to look for in the output:** The rule that fires (`root bypass` / `owner match` / `group match` / `other`), and then the read/write/exec verdict for each — verified against the actual `access(2)` syscall result.

```bash
# Compare two files with different permission models
python3 fs_probe.py --probe perm-walk --path /etc/passwd    # 644, owner=root
python3 fs_probe.py --probe perm-walk --path /etc/shadow    # 640, group=shadow
python3 fs_probe.py --probe perm-walk --path /usr/bin/sudo  # SUID binary
python3 fs_probe.py --probe perm-walk --path /tmp           # sticky bit directory
```

---

### Probe 4 — `delete-open`
**The kernel mechanic:** `unlink(2)` calls `vfs_unlink()` → removes the dentry (directory entry) → decrements `i_nlink`. But if a process still holds an fd open, `i_count` (the in-memory ref) is still nonzero. The kernel only calls `evict_inode()` when **both** `i_nlink == 0` and `i_count == 0`. Until then, the inode blocks stay on disk and in the page cache. `/proc/self/fd/<n>` shows the target as `(deleted)` — the kernel's acknowledgement that the dentry is gone but the inode is alive.

**What to look for in the output:** The `(deleted)` annotation in `/proc/self/fd/`, proof that `read()` still works through the fd after `unlink()`, and the inode number confirmed in `/proc/self/fdinfo/` matching the pre-deletion `stat()`.

```bash
python3 fs_probe.py --probe delete-open
```

**Real-world relevance:** This is why `lsof +L1` is part of disk-space debugging. `df` shows the filesystem is full; `du` shows nothing. The gap is deleted-but-held-open inodes — log files held by a crashed daemon that never reopened them after rotation.

---

### Probe 5 — `hard-vs-soft`
**The kernel mechanic:** A hard link (`link(2)`) creates a new dentry pointing to the same inode object — `vfs_link()` → `d_instantiate()`. A symlink (`symlink(2)`) creates an entirely new inode whose file data IS the target path string — on most modern kernels, if the path fits in ~60 bytes, it's stored directly in the inode itself (fast symlink, no extra block allocation). `lstat(2)` stops at the symlink inode; `stat(2)` follows the stored string through a full path re-resolution (`follow_link()`). Hard links cannot cross filesystem boundaries because inode numbers are only meaningful within one fs — a hard link on ext4 inode 12345 has no meaning on tmpfs.

**What to look for in the output:** `original.txt` and `hardlink.txt` sharing the same inode number. `softlink.txt` having its own distinct inode, with `st_size` equal to the length of the path string it stores. The dangling symlink: `lstat()` succeeds (the symlink inode exists), `stat()` returns ENOENT (the target path can't be resolved).

```bash
python3 fs_probe.py --probe hard-vs-soft
```

---

## Run all probes

```bash
bash setup/plant.sh           # set up test environment
python3 fs_probe.py           # run all five probes in sequence
bash setup/cleanup.sh         # tear down
```

---

## Where it breaks

**Probe 1 — inode-map:** Hard links across filesystems will fail with `EXDEV` (`errno 18` — invalid cross-device link). Try `ln /tmp/something /home/user/something` if `/tmp` and `/home` are on different filesystems. The inode number is only meaningful within one block device.

**Probe 2 — fd-table:** Reading `/proc/<pid>/fd/` for another user's process without `sudo` returns `EACCES`. The kernel enforces this — `ptrace_may_access()` gates fd table visibility. Try `python3 fs_probe.py --probe fd-table --pid 1` without sudo and watch it fail.

**Probe 3 — perm-walk:** The permission check is a first-match-wins rule. If you're in the file's owner group but you're also the owner, the **owner bits** apply — not the group bits. This is why `chmod 070 file; chown yourself file` doesn't give group access to yourself: owner bits matched first and they're `---`. Test it deliberately.

**Probe 4 — delete-open:** On filesystems that don't support `O_TMPFILE`, some operations behave differently. Also: `unlink()` and `rm` both call `unlink(2)` — `rm` does not shred or zero data. The blocks stay in place until the inode is evicted and the blocks are reallocated. Forensic tools can often recover the content.

**Probe 5 — hard-vs-soft:** Symlink loops (`a → b → a`) are stopped by the kernel with `ELOOP` after 40 dereferences (configurable). Hard links to directories are forbidden by default even as root — `link(2)` returns `EPERM`. The kernel disallows this to preserve the directory tree as a DAG; otherwise `fsck` and path traversal would face cycles.

---

## Theory connection

| Probe | Academic concept | Where it lives in the kernel |
|-------|-----------------|------------------------------|
| inode-map | Inode as the file identity unit; dentry as the name binding | `struct inode` in `include/linux/fs.h` |
| fd-table | Per-process file descriptor table; `struct file` as open file description | `struct files_struct`, `fdtable` in `include/linux/fdtable.h` |
| perm-walk | DAC, UID/GID credential model, SUID execution model | `inode_permission()` in `fs/namei.c` |
| delete-open | Inode reference counting; `i_count` vs `i_nlink` | `iput()`, `evict_inode()` in `fs/inode.c` |
| hard-vs-soft | Dentry vs inode; fast symlinks; VFS path resolution | `vfs_link()`, `vfs_symlink()`, `follow_link()` in `fs/namei.c` |

The `/proc` filesystem you're reading in probe 2 is itself a VFS implementation — `procfs` — where "files" have no backing storage. Every read triggers a kernel function that synthesizes the content on demand. The same VFS interface (`open`, `read`, `stat`) works on ext4 on a disk, tmpfs in RAM, and procfs with no disk at all. That's the abstraction.
