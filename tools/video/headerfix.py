"""Rebuild MOV/MP4 files whose first encrypted segment (ftyp/moov/mdat header) was lost.

usage (root on NAS): python3 headerfix.py DEVICE CHUNKMAP JOBS LIST OUT_DIR SRC_DIR [SEARCH_MIB] > report.jsonl
LIST: one relative path per line (files under SRC_DIR with a zeroed head).
Finds the file's moov either intact at EOF or as a freed block on the device near the file's known extents
(signature "moov" + mvhd), accepts it only if >=80% of its video samples that land in the file's surviving
plaintext validate (NAL length framing), then writes ftyp + free + mdat header in front of the first chunk
and appends the moov at EOF when it was not already there. Output is a new file in OUT_DIR.
"""
import bisect, json, os, shutil, struct, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import movsamples as ms

dev, chunkmap, jobs_path, lst, out_dir, src_dir = sys.argv[1:7]
SEARCH = (int(sys.argv[7]) if len(sys.argv) > 7 else 512) << 20
chunks = sorted((int(a), int(b), int(c)) for a, b, c, _t in (l.split() for l in open(chunkmap)))
starts = [c[0] for c in chunks]
fd = os.open(dev, os.O_RDONLY)
SIGS = [b"moov\x00\x00\x00\x6cmvhd", b"moov\x00\x00\x00\x78mvhd"]


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


def video_samples_of(moov):
    with tempfile.NamedTemporaryFile(dir=os.environ.get("WORK_TMP", "/tmp"), delete=False) as t:
        t.write(moov)
        name = t.name
    try:
        return [(o, s) for k, c, o, s in ms.samples(name) if k == "vide" and c in (b"avc1", b"hvc1", b"hev1")], \
               min(o for k, c, o, s in ms.samples(name))
    finally:
        os.unlink(name)


def score(moov, path, size):
    try:
        vids, first = video_samples_of(moov)
    except Exception:
        return 0.0, None
    if not vids or max(o + s for o, s in vids) > size:
        return 0.0, None
    good = tested = 0
    with open(path, "rb") as f:
        for o, s in vids[len(vids) // 10::max(1, len(vids) // 60)]:
            f.seek(o)
            b = f.read(s)
            if b.count(0) == len(b):
                continue  # still zero (unrecovered) -> says nothing
            tested += 1
            good += ms.nal_ok(b)
    return (good / tested if tested >= 10 else 0.0), first


jobs = {}
for line in open(jobs_path, encoding="utf-8"):
    j = json.loads(line)
    jobs[j["rel"]] = j

for rel in (l.rstrip("\n") for l in open(lst, encoding="utf-8")):
    src = os.path.join(src_dir, rel)
    rep = {"rel": rel}
    try:
        size = os.path.getsize(src)
        moov, at_end = None, False
        with open(src, "rb") as f:  # 1) intact at EOF?
            n = min(size, 32 << 20)
            f.seek(size - n)
            tail = f.read(n)
        i = tail.rfind(b"moov")
        while i != -1 and moov is None:
            if i >= 4 and struct.unpack(">I", tail[i - 4:i])[0] == n - (i - 4):
                moov, at_end = tail[i - 4:], True
            i = tail.rfind(b"moov", 0, i)
        best = (0.0, None, None)
        if moov is not None:
            best = score(moov, src, size) + (moov,)
        else:  # 2) freed block near the file's extents
            centers = sorted({e[1] for e in jobs.get(rel, {}).get("extents", [])})
            seen = set()
            for a, ln, p in chunks:
                if not any(a + ln >= c - SEARCH and a <= c + SEARCH for c in centers):
                    continue
                for off in range(0, ln, 64 << 20):
                    buf = os.pread(fd, min(64 << 20, ln - off) + 16, p + off)
                    for sig in SIGS:
                        j = buf.find(sig)
                        while j != -1:
                            lg = a + off + j - 4
                            if lg not in seen:
                                seen.add(lg)
                                hdr = read_logical(lg, 4)
                                msz = struct.unpack(">I", hdr)[0] if hdr else 0
                                if 16 < msz < (64 << 20):
                                    cand = read_logical(lg, msz)
                                    sc = score(cand, src, size) if cand else (0.0, None)
                                    if sc[0] > best[0]:
                                        best = sc + (cand,)
                            j = buf.find(sig, j + 1)
            rep["candidates"] = len(seen)
        sc, first, moov = best
        rep["score"] = round(sc, 3)
        if sc < 0.8 or first is None:
            rep["status"] = "NO_MOOV"
            print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
            continue
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".tmp-hdr"
        shutil.copyfile(src, tmp)
        data_end = size - len(moov) if at_end else size
        mdat_len = data_end - first + 8
        hdr_len = 8 if mdat_len < 2 ** 32 else 16
        mdat_at = first - hdr_len
        ftyp = (b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  " if rel.lower().endswith(".mov")
                else b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom")
        if mdat_at < len(ftyp) + 8 and mdat_at != len(ftyp):
            raise ValueError("no room for header before first chunk")
        with open(tmp, "r+b") as f:
            f.seek(0)
            f.write(ftyp)
            gap = mdat_at - len(ftyp)
            if gap:
                f.write(struct.pack(">I", gap) + b"free" + bytes(gap - 8))
            if hdr_len == 8:
                f.write(struct.pack(">I", data_end - mdat_at) + b"mdat")
            else:
                f.write(struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", data_end - mdat_at))
            if not at_end:
                f.seek(0, 2)
                f.write(moov)
        os.rename(tmp, dest)
        rep.update(status="REBUILT", moov_from="eof" if at_end else "disk", first_chunk=first)
    except FileExistsError:
        rep["status"] = "EXISTS"
    except Exception as e:
        rep["status"] = "ERR"
        rep["err"] = str(e)[:200]
    print(json.dumps(rep, ensure_ascii=False)); sys.stdout.flush()
