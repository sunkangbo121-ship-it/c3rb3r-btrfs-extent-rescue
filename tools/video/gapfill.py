"""Fill zeroed (unrecovered) ranges of a MOV/MP4 by locating freed extents on the raw device, frame by frame.

usage (root on NAS): python3 gapfill.py DEVICE CHUNKMAP JOBS IN_DIR OUT_DIR [SEARCH_MIB] > report.jsonl
Needs a moov in each input file (run videofix.py first when it was lost). For every video sample that
fails NAL-length validation, the bytes are looked up on the device:
  * btrfs data extents are 4 KiB aligned in both file and logical space, so logical % 4096 == file_off % 4096;
  * most samples are a single NAL whose 4-byte length prefix is size-4 -> a precise search key;
  * a candidate mapping (delta = logical - file_off) is accepted only if this and the next samples validate,
    then it is reused for following samples until one fails.
Only bytes of samples that validate (plus the bytes between two consecutive validated samples under the same
mapping, which hold interleaved audio) are written. Inputs are untouched; output is O_EXCL.
"""
import bisect, json, os, shutil, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import movsamples as ms

dev, chunkmap, jobs_path, in_dir, out_dir = sys.argv[1:6]
SEARCH = (int(sys.argv[6]) if len(sys.argv) > 6 else 1024) << 20
MAX_SEARCHES = 60
chunks = sorted((int(a), int(b), int(c)) for a, b, c, _t in (l.split() for l in open(chunkmap)))
starts = [c[0] for c in chunks]
fd = os.open(dev, os.O_RDONLY)


def read_logical(lg, n):
    out = bytearray()
    while n > 0:
        i = bisect.bisect_right(starts, lg) - 1
        if i < 0:
            return None
        a, ln, p = chunks[i]
        if lg >= a + ln:
            return None
        k = min(n, a + ln - lg)
        out += os.pread(fd, k, p + lg - a)
        lg += k
        n -= k
    return bytes(out)


def ok_at(delta, off, size):
    b = read_logical(off + delta, size)
    return b is not None and ms.nal_ok(b)


def find_delta(off, size, nxt, centers):
    """Search near centers for a logical position holding this sample; confirm with following samples."""
    key = struct.pack(">I", size - 4)
    want = off % 4096
    tried = set()
    for c in centers:
        lo = max(0, c - SEARCH)
        hi = c + SEARCH
        for a, ln, p in chunks:
            if a + ln < lo or a > hi:
                continue
            s, e = max(a, lo), min(a + ln, hi)
            for blk in range(s, e, 64 << 20):
                n = min(64 << 20, e - blk)
                buf = os.pread(fd, n + 8, p + blk - a)
                i = buf.find(key)
                while i != -1:
                    lg = blk + i
                    if lg % 4096 == want:
                        d = lg - off
                        if d not in tried:
                            tried.add(d)
                            if ok_at(d, off, size) and all(ok_at(d, o2, s2) for o2, s2 in nxt):
                                return d
                    i = buf.find(key, i + 1)
    return None


jobs = {}
for line in open(jobs_path, encoding="utf-8"):
    j = json.loads(line)
    jobs[j["rel"]] = j

for dirpath, _d, files in os.walk(in_dir):
    for name in files:
        if not name.lower().endswith((".mov", ".mp4")):
            continue
        src = os.path.join(dirpath, name)
        rel = os.path.relpath(src, in_dir)
        rep = {"rel": rel}
        try:
            vids = sorted((o, s) for k, c, o, s in ms.samples(src) if k == "vide" and c in (b"avc1", b"hvc1", b"hev1"))
            with open(src, "rb") as f:
                bad = []
                for o, s in vids:
                    f.seek(o)
                    if not ms.nal_ok(f.read(s)):
                        bad.append((o, s))
            rep.update(video_samples=len(vids), bad_before=len(bad))
            if not bad:
                rep["status"] = "NOTHING_TO_DO"
                print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
                continue
            ext = jobs.get(rel, {}).get("extents", [])
            centers = sorted({e[1] for e in ext})
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            tmp = dest + ".tmp-gap"
            shutil.copyfile(src, tmp)
            filled = 0
            delta = None
            prev = None  # (end_offset, delta) of the last sample written under the current mapping
            searches, skip_until = 0, -1
            with open(tmp, "r+b") as out:
                for idx, (o, s) in enumerate(bad):
                    nxt = bad[idx + 1:idx + 3]
                    if delta is None or not ok_at(delta, o, s):
                        if o < skip_until or searches >= MAX_SEARCHES:
                            delta = None
                            continue
                        # nearest known extents by file offset, mapped to where offset o would sit in them
                        near = sorted(ext, key=lambda e: min(abs(o - e[0]), abs(o - (e[0] + e[3]))))[:3]
                        cs = ([o + delta] if delta is not None else []) + [e[1] + (o - e[0]) for e in near]
                        delta = find_delta(o, s, nxt, cs)
                        searches += 1
                        prev = None
                        if delta is None:
                            skip_until = o + (1 << 20)  # this extent is most likely overwritten; try further on
                            continue
                    start = o
                    if prev and prev[1] == delta and prev[0] <= o and o - prev[0] < (8 << 20):
                        start = prev[0]  # interleaved audio between two frames of the same extent
                    data = read_logical(start + delta, o + s - start)
                    out.seek(start)
                    out.write(data)
                    filled += o + s - start
                    prev = (o + s, delta)
            still = 0
            with open(tmp, "rb") as f:
                for o, s in vids:
                    f.seek(o)
                    if not ms.nal_ok(f.read(s)):
                        still += 1
            os.rename(tmp, dest)
            rep.update(status="FILLED" if still == 0 else "IMPROVED" if still < len(bad) else "NO_GAIN",
                       bad_after=still, bytes_filled=filled)
        except FileExistsError:
            rep["status"] = "EXISTS"
        except Exception as e:
            rep["status"] = "ERR"
            rep["err"] = str(e)[:200]
        print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
