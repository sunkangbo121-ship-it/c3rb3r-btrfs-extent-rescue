"""Repair partially recovered MOV/MP4 files whose trailing encrypted segment (with the moov atom) was not found.

usage (root on NAS): python3 videofix.py DEVICE CHUNKMAP JOBS PARTIAL_DIR OUT_DIR [SEARCH_GIB] > report.jsonl
For each .mov/.mp4 under PARTIAL_DIR whose moov is missing:
  1. moov offset/size follow from the mdat header (moov assumed last); search the raw device near the
     file's known extents for be32(moov_size)+"moov".
  2. Treat the hit as the tail of a contiguous freed extent; fill the missing tail from it.
  3. Validate every video sample in the filled range (NAL length framing); keep only the longest valid
     suffix ending at the moov, zero the rest. Output goes to OUT_DIR (O_EXCL); originals untouched.
"""
import bisect, json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import movsamples as ms

dev, chunkmap, jobs_path, partial_dir, out_dir = sys.argv[1:6]
SEARCH = int(sys.argv[6]) << 20 if len(sys.argv) > 6 else 512 << 20  # MiB either side of known extents
chunks = sorted((int(a), int(b), int(c)) for a, b, c, _t in (l.split() for l in open(chunkmap)))
starts = [c[0] for c in chunks]
fd = os.open(dev, os.O_RDONLY)


def read_logical(lg, n):
    out = bytearray()
    while n > 0:
        i = bisect.bisect_right(starts, lg) - 1
        if i < 0:
            raise ValueError("unmapped")
        a, ln, p = chunks[i]
        if lg >= a + ln:
            raise ValueError("unmapped")
        k = min(n, a + ln - lg)
        out += os.pread(fd, k, p + lg - a)
        lg += k
        n -= k
    return bytes(out)


def search(sig, centers):
    hits = []
    for a, ln, p in chunks:
        if not any(a + ln >= c - SEARCH and a <= c + SEARCH for c in centers):
            continue
        for off in range(0, ln, 64 << 20):
            buf = os.pread(fd, min(64 << 20, ln - off) + len(sig), p + off)
            i = buf.find(sig)
            while i != -1:
                hits.append(a + off + i)
                i = buf.find(sig, i + 1)
    return hits


jobs = {}
for line in open(jobs_path, encoding="utf-8"):
    j = json.loads(line)
    jobs[j["rel"]] = j

for dirpath, _dirs, files in os.walk(partial_dir):
    for name in files:
        if not name.lower().endswith((".mov", ".mp4")):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, partial_dir)
        rep = {"rel": rel}
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                atoms = list(ms.top_level(f, size))
            names = [t for t, _p, _s in atoms]
            rep["atoms"] = [t.decode("latin1") for t in names]
            if b"moov" in names:
                rep["status"] = "HAS_MOOV"
                print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
                continue
            mdat = [(p, s) for t, p, s in atoms if t == b"mdat"]
            if not mdat:
                raise ValueError("no mdat")
            moov_off = mdat[0][0] + mdat[0][1]
            moov_size = size - moov_off
            rep.update(moov_off=moov_off, moov_size=moov_size)
            if not 8 < moov_size < 64 << 20:
                raise ValueError("implausible moov size")
            centers = [e[1] for e in jobs.get(rel, {}).get("extents", [])]
            if not centers:
                raise ValueError("no extents to search near")
            hits = search(struct.pack(">I", moov_size) + b"moov", centers)
            rep["hits"] = len(hits)
            if not hits:
                rep["status"] = "MOOV_NOT_FOUND"
                print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
                continue
            hit = min(hits, key=lambda h: min(abs(h - c) for c in centers))
            # first zero run in the file's last 6% = start of the missing tail
            with open(path, "rb") as f:
                scan_from = max(0, int(size * 0.94))
                f.seek(scan_from)
                tail = f.read(moov_off - scan_from)
            z = tail.find(bytes(4096))
            if z == -1:
                raise ValueError("no missing tail found")
            # zero runs start on a 4 KiB extent boundary; round up so recovered bytes are never overwritten
            fill_from = -(-(scan_from + z) // 4096) * 4096
            data = read_logical(hit - (moov_off - fill_from), size - fill_from)
            if data[moov_off - fill_from + 4:moov_off - fill_from + 8] != b"moov":
                raise ValueError("moov misaligned")
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            tmp = dest + ".tmp-fix"
            with open(path, "rb") as src, open(tmp, "xb") as dst:
                pos = 0
                while pos < fill_from:
                    k = min(32 << 20, fill_from - pos)
                    dst.write(src.read(k)); pos += k
                dst.write(data)
            # validate video samples in the filled range; keep the longest valid suffix
            smp = [x for x in ms.samples(tmp) if x[0] == "vide" and x[1] in (b"avc1", b"hvc1", b"hev1")]
            bad_end = fill_from
            with open(tmp, "r+b") as f:
                for _k, _c, off, sz in smp:
                    if off + sz <= fill_from or off >= moov_off:
                        continue
                    f.seek(off)
                    if not ms.nal_ok(f.read(sz)):
                        bad_end = max(bad_end, off + sz)
                if bad_end > fill_from:  # zero the unverifiable part instead of keeping foreign bytes
                    f.seek(fill_from)
                    f.write(bytes(bad_end - fill_from))
            os.rename(tmp, dest)
            bad_samples = 0
            first_bad = None
            with open(dest, "rb") as f:
                for _k, _c, off, sz in smp:
                    f.seek(off)
                    if not ms.nal_ok(f.read(sz)):
                        bad_samples += 1
                        first_bad = off if first_bad is None else first_bad
            rep.update(status="FIXED" if bad_samples == 0 else "FIXED_TRIM_NEEDED", fill_from=fill_from,
                       restored=size - bad_end, bad_video_samples=bad_samples, first_bad_offset=first_bad,
                       video_samples=len(smp))
        except FileExistsError:
            rep["status"] = "EXISTS"
        except Exception as e:
            rep["status"] = "ERR"
            rep["err"] = str(e)[:200]
        print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
