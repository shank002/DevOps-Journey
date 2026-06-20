#!/usr/bin/env bash
# setup/plant.sh
# Creates a test directory tree under /tmp/fs-probe-lab with:
#   - regular files
#   - hard links (multiple names → same inode)
#   - symlinks (including a dangling one)
#   - a SUID binary (for perm-walk to examine)
#   - a world-writable file
#   - a directory with sticky bit
#
# Run this before:  python3 fs_probe.py --probe inode-map

set -euo pipefail

BASE=/tmp/fs-probe-lab
echo "[plant] creating $BASE"
rm -rf "$BASE"
mkdir -p "$BASE/subdir"

# Regular files
echo "I am file A" > "$BASE/file-a.txt"
echo "I am file B" > "$BASE/subdir/file-b.txt"
dd if=/dev/urandom bs=1K count=4 of="$BASE/random-4k.bin" 2>/dev/null

# Hard links: two names, one inode
echo "shared content" > "$BASE/hardlink-original.txt"
ln "$BASE/hardlink-original.txt" "$BASE/hardlink-alias.txt"
ln "$BASE/hardlink-original.txt" "$BASE/subdir/hardlink-third.txt"

echo "[plant] hard links created:"
ls -lai "$BASE/hardlink-original.txt" "$BASE/hardlink-alias.txt" "$BASE/subdir/hardlink-third.txt"

# Symlink pointing to a real file
ln -s "$BASE/file-a.txt" "$BASE/symlink-to-a.txt"

# Dangling symlink (target doesn't exist)
ln -s "$BASE/does-not-exist.txt" "$BASE/dangling-symlink.txt"

# World-writable file (shows up in audit scans)
touch "$BASE/world-writable.txt"
chmod 0666 "$BASE/world-writable.txt"

# Sticky-bit directory (like /tmp — only owner can delete their own files)
mkdir -p "$BASE/sticky-dir"
chmod 1777 "$BASE/sticky-dir"
touch "$BASE/sticky-dir/owned-by-you.txt"

echo ""
echo "[plant] tree:"
ls -lai "$BASE"
echo ""
echo "[plant] done. Run: python3 fs_probe.py --probe inode-map --dir $BASE"
