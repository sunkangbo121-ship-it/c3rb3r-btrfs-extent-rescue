"""Map every live encrypted file under PREFIX to the pre-attack extents found in orphaned leaves.

usage: python3 make_jobs.py ORPHAN_ITEMS.jsonl CUTOFF_GEN ENCRYPTED_LIST.tsv PREFIX JOBS.jsonl
  PREFIX = path of the target directory relative to the subvolume root, e.g. USER/Photos/
  ENCRYPTED_LIST.tsv lines: size<TAB>path-under-PREFIX.L0CK3D
jobs line: {"rel": path under PREFIX (without .L0CK3D), "ino": ..., "extents": [[foff, dbytenr, eoff, nbytes], ...]}
Files are matched by (parent chain, name) path; a live file with no old extents is skipped.
"""
import collections, json, sys

items_path, cutoff, listing, prefix, jobs_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
names = collections.defaultdict(collections.Counter)
exts = collections.defaultdict(dict)
for line in open(items_path, encoding="utf-8"):
    r = json.loads(line)
    t = r["t"]
    if t == "ref":
        for n in r["names"]:
            names[r["ino"]][(r["parent"], n)] += 1
    elif t == "dir":
        names[r["ino"]][(r["parent"], r["name"])] += 1
    elif t == "ext" and r["etype"] in (1, 2) and r["egen"] < cutoff and r.get("dbytenr") and not r["comp"]:
        cur = exts[r["ino"]].get(r["foff"])
        if cur is None or r["egen"] > cur[0]:
            exts[r["ino"]][r["foff"]] = (r["egen"], r["dbytenr"], r["eoff"], r["nbytes"])


def strip(n):
    return n[:-7] if n.endswith(".L0CK3D") else n


def paths_of(ino, depth=0):
    """All plausible paths (names may differ between generations)."""
    if ino == 256:
        return {""}
    if depth > 40 or ino not in names:
        return set()
    out = set()
    for (parent, name) in names[ino]:
        for pp in paths_of(parent, depth + 1):
            out.add((pp + "/" if pp else "") + strip(name))
            if len(out) > 8:
                return out
    return out


live = {}
for line in open(listing, encoding="utf-8"):
    sz, rel = line.rstrip("\n").split("\t", 1)
    live[prefix + rel[:-7]] = rel[:-7]

stats = collections.Counter()
taken = set()
with open(jobs_path, "w", encoding="utf-8") as out:
    for ino, ex in exts.items():
        for p in paths_of(ino):
            if p in live and p not in taken:
                taken.add(p)
                stats["matched"] += 1
                out.write(json.dumps({"rel": live[p], "ino": ino,
                                      "extents": [[f, e[1], e[2], e[3]] for f, e in sorted(ex.items())]},
                                     ensure_ascii=False) + "\n")
                break
stats["live_files"] = len(live)
print(dict(stats))
