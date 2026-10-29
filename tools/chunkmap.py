"""Convert a text dump of the btrfs chunk tree into CHUNKMAP lines for the other tools.

usage:
  btrfs-debug-tree -t 3 /dev/mapper/vg1-volume_1 > chunk-tree.txt          # btrfs-progs 4.x (DSM)
  btrfs inspect-internal dump-tree -t chunk /dev/... > chunk-tree.txt        # newer btrfs-progs
  python3 chunkmap.py chunk-tree.txt > chunkmap.txt

Output lines: logical length physical type   (physical = stripe 0)
Only single-device SINGLE / DUP profiles are supported (stripe 0 holds a full copy).
RAID0/5/6/10 chunks are reported on stderr and skipped; the tools would need real
stripe math for those. Read-only: this script only parses text.
"""
import re
import sys

KEY = re.compile(r"key \(FIRST_CHUNK_TREE CHUNK_ITEM (\d+)\)")
LEN = re.compile(r"\blength (\d+)")
TYPE = re.compile(r"\btype ([A-Z0-9|]+)")
STRIPE0 = re.compile(r"stripe 0 devid \d+ offset (\d+)")

cur = None
out = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = KEY.search(line)
    if m and "itemoff" in line:
        cur = {"logical": int(m.group(1))}
        continue
    if cur is None:
        continue
    for name, rx in (("length", LEN), ("type", TYPE), ("phys", STRIPE0)):
        m = rx.search(line)
        if m and name not in cur:
            cur[name] = m.group(1) if name == "type" else int(m.group(1))
    if {"length", "type", "phys"} <= cur.keys():
        t = cur["type"]
        if any(p in t for p in ("RAID0", "RAID5", "RAID6", "RAID10")):
            sys.stderr.write("skip striped chunk %d %s\n" % (cur["logical"], t))
        else:
            out.append((cur["logical"], cur["length"], cur["phys"], t))
        cur = None

for row in sorted(out):
    print("%d %d %d %s" % row)
sys.stderr.write("%d chunks\n" % len(out))
