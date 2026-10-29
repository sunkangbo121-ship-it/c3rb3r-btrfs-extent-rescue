"""Build a recovery plan from parsed orphan-leaf items: files under PREFIX whose pre-attack extents cover the whole file.

usage: python3 build_plan.py ORPHAN_ITEMS.jsonl CUTOFF_GEN PREFIX PLAN.jsonl [ENCRYPTED_LIST.tsv]
  PREFIX = target directory relative to the subvolume root, e.g. USER/Photos/
Output lines: {"path", "ino", "size", "extents": [[foff, dbytenr, eoff, nbytes], ...]}
"""
import collections, json, sys

items_path, cutoff, prefix, plan_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
# Optional: live encrypted listing "size<TAB>path-under-PREFIX" -> original size = size - 588 footer.
live_size = {}
if len(sys.argv) > 5:
    for line in open(sys.argv[5], encoding="utf-8"):
        sz, rel = line.rstrip("\n").split("\t", 1)
        if rel.endswith(".L0CK3D"):
            live_size[prefix + rel[:-7]] = int(sz) - 588
names = collections.defaultdict(collections.Counter)   # ino -> Counter((parent, name))
inodes = {}                                            # ino -> (transid, size, mode) latest pre-cutoff
exts = collections.defaultdict(dict)                   # ino -> foff -> (egen, dbytenr, eoff, nbytes, comp)
for line in open(items_path, encoding="utf-8"):
    r = json.loads(line)
    t = r["t"]
    if t == "ref":
        for n in r["names"]:
            names[r["ino"]][(r["parent"], n)] += 1
    elif t == "dir":
        names[r["ino"]][(r["parent"], r["name"])] += 1
    elif t == "inode":
        if r["transid"] < cutoff and (r["ino"] not in inodes or r["transid"] > inodes[r["ino"]][0]):
            inodes[r["ino"]] = (r["transid"], r["size"], r["mode"])
    elif t == "ext" and r["etype"] in (1, 2) and r["egen"] < cutoff and r.get("dbytenr"):
        cur = exts[r["ino"]].get(r["foff"])
        cand = (r["egen"], r["dbytenr"], r["eoff"], r["nbytes"], r["comp"])
        if cur is None or cand[0] > cur[0]:
            exts[r["ino"]][r["foff"]] = cand


def best_name(ino):
    c = names.get(ino)
    if not c:
        return None
    plain = [(k, v) for k, v in c.items() if not k[1].endswith(".L0CK3D")]
    pool = plain or list(c.items())
    return max(pool, key=lambda kv: kv[1])[0]


def path_of(ino, depth=0):
    if ino == 256:
        return ""
    if depth > 64:
        return None
    bn = best_name(ino)
    if bn is None:
        return None
    parent, name = bn
    pp = path_of(parent, depth + 1)
    if pp is None:
        return None
    return pp + "/" + name if pp else name


stats = collections.Counter()
with open(plan_path, "w", encoding="utf-8") as out:
    for ino in set(inodes) | set(exts):
        p = path_of(ino)
        if p is None:
            if ino in exts:
                stats["no_path_with_extents"] += 1
            continue
        if not p.startswith(prefix) or "/@eaDir" in p or p.endswith("read-me3.txt"):
            continue
        if ino in inodes and (inodes[ino][2] & 0o170000) != 0o100000:
            continue
        stats["target_files"] += 1
        if ino not in exts:
            stats["no_old_extents"] += 1
            continue
        if any(e[4] for e in exts[ino].values()):
            stats["compressed"] += 1
            continue
        size = inodes[ino][1] if ino in inodes else live_size.get(p)
        if ino not in inodes and size is not None:
            stats["size_from_footer"] += 1
        if size is None:
            stats["no_size"] += 1
            continue
        covered, ok = 0, True
        for foff in sorted(exts[ino]):
            if foff > covered:
                ok = False
                break
            covered = max(covered, foff + exts[ino][foff][3])
        if not ok or covered < size:
            stats["incomplete"] += 1
            continue
        stats["complete"] += 1
        stats["bytes"] += size
        out.write(json.dumps({"path": p, "ino": ino, "size": size,
                              "extents": [[f, e[1], e[2], e[3]] for f, e in sorted(exts[ino].items())]},
                             ensure_ascii=False) + "\n")
print(dict(stats), "GiB=%.1f" % (stats["bytes"] / 2**30))
