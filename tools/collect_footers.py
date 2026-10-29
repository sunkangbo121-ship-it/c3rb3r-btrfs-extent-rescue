"""Read the last 588 bytes of sample *.L0CK3D files (read-only) and print JSON lines.
Usage on NAS: sudo python3 - ROOT MAX_FILES < collect_footers.py > footers.jsonl
Output contains footer[0:48] ("rec", the wrapped per-file key record) and the first 16 bytes
("head") of each file: treat it as private evidence, never publish it.
"""
import json, os, struct, sys

root, limit = sys.argv[1], int(sys.argv[2])
seen = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d != "@eaDir"]
    for name in filenames:
        if not name.endswith(".L0CK3D"):
            continue
        path = os.path.join(dirpath, name)
        try:
            st = os.lstat(path)
            if st.st_size < 588 or not os.path.isfile(path) or os.path.islink(path):
                continue
            with open(path, "rb") as f:
                f.seek(-588, 2)
                foot = f.read(588)
                f.seek(0)
                head = f.read(16)
        except OSError:
            continue
        print(json.dumps({"path": path, "size": st.st_size, "mtime": st.st_mtime,
                          "marker": foot[568:572].hex(), "mode": foot[572], "pct": foot[573],
                          "crypto": foot[574], "orig": struct.unpack_from("<Q", foot, 580)[0],
                          "rec": foot[:48].hex(), "head": head.hex()}, ensure_ascii=False))
        seen += 1
        if seen >= limit:
            sys.exit(0)
