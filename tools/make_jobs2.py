"""Jobs for every live encrypted file under PREFIX, using the current tree plus orphaned old leaves.

usage: python3 make_jobs2.py CURRENT_ITEMS.jsonl ORPHAN_ITEMS.jsonl CUTOFF ENCRYPTED_LIST.tsv PREFIX JOBS.jsonl
  PREFIX = target directory relative to the subvolume root, e.g. USER/Photos/
  ENCRYPTED_LIST.tsv lines: size<TAB>path-under-PREFIX.L0CK3D
  ORPHAN_ITEMS.jsonl may be an empty file if no orphaned leaves were parsed.
Extent list order: exact pre-attack refs first, then whole-extent refs synthesized from
still-referenced old extents (file offset foff-eoff, extent byte 0, full disk_num_bytes).
"""
import collections, json, sys

cur_path, old_path, cutoff, listing, prefix, out_path = (sys.argv[1], sys.argv[2], int(sys.argv[3]),
                                                         sys.argv[4], sys.argv[5], sys.argv[6])

names = {}
cur_ext = collections.defaultdict(list)
for line in open(cur_path, encoding="utf-8"):
    r = json.loads(line)
    if r["t"] == "ref":
        names[r["ino"]] = (r["parent"], r["names"][0])
    elif r["t"] == "ext" and r["etype"] in (1, 2) and r.get("dbytenr") and not r["comp"]:
        cur_ext[r["ino"]].append(r)

old_ext = collections.defaultdict(dict)
for line in open(old_path, encoding="utf-8"):
    r = json.loads(line)
    if r["t"] == "ext" and r["etype"] in (1, 2) and r.get("dbytenr") and not r["comp"] and r["egen"] < cutoff:
        cur = old_ext[r["ino"]].get(r["foff"])
        if cur is None or r["egen"] > cur["egen"]:
            old_ext[r["ino"]][r["foff"]] = r


def path_of(ino, depth=0):
    if ino == 256:
        return ""
    if depth > 40 or ino not in names:
        return None
    parent, name = names[ino]
    pp = path_of(parent, depth + 1)
    return None if pp is None else (pp + "/" + name if pp else name)


live = {}
for line in open(listing, encoding="utf-8"):
    _sz, rel = line.rstrip("\n").split("\t", 1)
    live[prefix + rel] = rel[:-7]

stats = collections.Counter()
with open(out_path, "w", encoding="utf-8") as out:
    for ino in names:
        p = path_of(ino)
        if p not in live:
            continue
        stats["live_matched"] += 1
        exact = [[e["foff"], e["dbytenr"], e["eoff"], e["nbytes"]] for _f, e in sorted(old_ext.get(ino, {}).items())]
        synth, seen = [], set()
        for e in cur_ext.get(ino, []) + list(old_ext.get(ino, {}).values()):
            if e["egen"] >= cutoff:
                continue
            key = (e["foff"] - e["eoff"], e["dbytenr"])
            if key in seen or key[0] < 0:
                continue
            seen.add(key)
            synth.append([key[0], e["dbytenr"], 0, e["dnum"]])
        if not exact and not synth:
            stats["no_old_extent"] += 1
            continue
        stats["with_exact"] += bool(exact)
        stats["with_synth"] += bool(synth)
        out.write(json.dumps({"rel": live[p], "ino": ino, "extents": exact + synth}, ensure_ascii=False) + "\n")
stats["live_total"] = len(live)
print(dict(stats))
