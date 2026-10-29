"""Parse orphaned btrfs fs-tree leaves of one subvolume straight from the block device.

Usage on NAS (root, read-only):
  python3 - DEVICE CHUNKMAP LEAFLIST OWNER < parse_leaves.py > items.jsonl
DEVICE = underlying LV, e.g. /dev/mapper/vg1-volume_1 (opened O_RDONLY)
CHUNKMAP lines: logical length physical type   (stripe 0, single/DUP)
LEAFLIST lines: gen level bytenr                (from btrfs-find-root -a -o OWNER)
Emits one JSON object per INODE_ITEM / INODE_REF / DIR_INDEX / EXTENT_DATA item,
tagged with the leaf generation. Never writes to the device.
"""
import bisect, json, os, struct, sys

dev, chunkmap, leaflist, owner = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
NODESIZE = 16384
HDR = 101

chunks = []
for line in open(chunkmap):
    lg, ln, ph, _t = line.split()
    chunks.append((int(lg), int(ln), int(ph)))
chunks.sort()
starts = [c[0] for c in chunks]


def phys(logical):
    i = bisect.bisect_right(starts, logical) - 1
    if i < 0:
        return None
    lg, ln, ph = chunks[i]
    if logical >= lg + ln:
        return None
    return ph + (logical - lg)


fd = os.open(dev, os.O_RDONLY)
seen = set()
stats = {"leaves": 0, "bad": 0, "items": 0}
for line in open(leaflist):
    gen, level, bytenr = (int(x) for x in line.split())
    if level != 0 or bytenr in seen:
        continue
    seen.add(bytenr)
    p = phys(bytenr)
    if p is None:
        stats["bad"] += 1
        continue
    blk = os.pread(fd, NODESIZE, p)
    h_bytenr, = struct.unpack_from("<Q", blk, 48)
    h_gen, h_owner, nritems = struct.unpack_from("<QQI", blk, 80)
    h_level = blk[100]
    if h_bytenr != bytenr or h_owner != owner or h_level != 0 or nritems > 1000:
        stats["bad"] += 1
        continue
    stats["leaves"] += 1
    for i in range(nritems):
        objid, typ, off, doff, dsize = struct.unpack_from("<QBQII", blk, HDR + i * 25)
        d = HDR + doff
        if d + dsize > NODESIZE:
            continue
        rec = None
        if typ == 1:  # INODE_ITEM
            igen, transid, size, nbytes = struct.unpack_from("<QQQQ", blk, d)
            mode, = struct.unpack_from("<I", blk, d + 52)
            mtime, = struct.unpack_from("<Q", blk, d + 136)
            rec = {"t": "inode", "ino": objid, "size": size, "mode": mode, "transid": transid, "mtime": mtime}
        elif typ == 12:  # INODE_REF (offset = parent dir)
            names, q = [], d
            while q < d + dsize:
                _idx, nlen = struct.unpack_from("<QH", blk, q)
                names.append(blk[q + 10:q + 10 + nlen].decode("utf-8", "replace"))
                q += 10 + nlen
            rec = {"t": "ref", "ino": objid, "parent": off, "names": names}
        elif typ == 96:  # DIR_INDEX (objid = parent dir)
            child, = struct.unpack_from("<Q", blk, d)
            nlen, = struct.unpack_from("<H", blk, d + 27)
            name = blk[d + 30:d + 30 + nlen].decode("utf-8", "replace")
            rec = {"t": "dir", "parent": objid, "ino": child, "name": name}
        elif typ == 108:  # EXTENT_DATA (offset = file offset)
            egen, ram, comp, _enc, _oth, etype = struct.unpack_from("<QQBBHB", blk, d)
            rec = {"t": "ext", "ino": objid, "foff": off, "egen": egen, "comp": comp, "etype": etype}
            if etype == 0:
                rec["inline_len"] = dsize - 21
                rec["ram"] = ram
            else:
                dbytenr, dnum, eoff, nbytes = struct.unpack_from("<QQQQ", blk, d + 21)
                rec.update(dbytenr=dbytenr, dnum=dnum, eoff=eoff, nbytes=nbytes)
        if rec:
            rec["lgen"] = h_gen
            rec["leaf"] = bytenr
            stats["items"] += 1
            print(json.dumps(rec, ensure_ascii=False))
sys.stderr.write(json.dumps(stats) + "\n")
