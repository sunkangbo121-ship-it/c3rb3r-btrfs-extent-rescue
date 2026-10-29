"""Execute the merge plan on the NAS with reflink clones (no extra space, sources untouched).

usage (root): python3 merge_exec.py PLAN.tsv FINAL_DIR SUSPECT_DIR OWNER_UID OWNER_GID > merge-report.jsonl
Rows flagged "eoi" must end with a JPEG EOI / PNG IEND marker, otherwise they go to SUSPECT_DIR.
"""
import collections, fcntl, json, os, sys

plan, final, suspect, uid, gid = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
FICLONE = 0x40049409
stats = collections.Counter()


def ends_ok(path):
    with open(path, "rb") as f:
        head = f.read(8)
        f.seek(max(0, os.path.getsize(path) - 4096))
        tail = f.read()
    if head[:3] == b"\xff\xd8\xff":
        return b"\xff\xd9" in tail[-64:]
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return b"IEND" in tail[-32:]
    return True


def makedirs(d, root):
    if os.path.isdir(d):
        return
    makedirs(os.path.dirname(d), root)
    os.mkdir(d, 0o755)
    os.chown(d, uid, gid)


for line in open(plan, encoding="utf-8"):
    kind, src, rel, check = line.rstrip("\n").split("\t")
    try:
        root = final
        if check == "eoi" and not ends_ok(src):
            root = suspect
            stats["suspect"] += 1
        dest = os.path.join(root, rel)
        makedirs(os.path.dirname(dest), root)
        s = os.open(src, os.O_RDONLY)
        d = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            fcntl.ioctl(d, FICLONE, s)
        finally:
            os.close(s)
            os.close(d)
        os.chown(dest, uid, gid)
        stats[kind] += 1
    except FileExistsError:
        stats["exists"] += 1
    except Exception as e:
        stats["error"] += 1
        print(json.dumps({"rel": rel, "src": src, "err": str(e)[:160]}, ensure_ascii=False))
print(json.dumps(dict(stats), ensure_ascii=False))
