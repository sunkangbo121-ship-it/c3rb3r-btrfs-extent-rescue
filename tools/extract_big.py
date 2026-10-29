"""Streaming variant of extract_jobs.py for very large files (bounded memory).

usage (root on NAS): python3 - DEVICE CHUNKMAP PHOTOS_ROOT JOBS OUT_DIR PARTIAL_DIR MIN_SIZE < extract_big.py > report.jsonl
Only jobs whose original size >= MIN_SIZE are processed. Same splice rules as extract_jobs.py:
live plaintext outside the footer's encrypted ranges, pre-attack extents inside them, exact refs first,
read-backs identical to the current ciphertext rejected. Output written to a .tmp name, then renamed
to a path that must not exist.
"""
import bisect, json, os, struct, sys

dev, chunkmap, photos, jobs, out_dir, partial_dir, min_size = sys.argv[1:8]
min_size = int(min_size)
FOOTER = 588
FIRST_LIMIT = 1 << 20
STEP = 32 << 20
PARTIAL_FACTORS = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12, 40: 14, 50: 10, 60: 20, 70: 23, 80: 27}
MIN_PARTIAL_COVER = float(os.environ.get("MIN_PARTIAL_COVER", "0.5"))

chunks = sorted((int(a), int(b), int(c)) for a, b, c, _t in (l.split() for l in open(chunkmap)))
starts = [c[0] for c in chunks]


def read_logical(fd, logical, length):
    out = bytearray()
    while length > 0:
        i = bisect.bisect_right(starts, logical) - 1
        if i < 0:
            raise ValueError("unmapped logical %d" % logical)
        lg, ln, ph = chunks[i]
        if logical >= lg + ln:
            raise ValueError("unmapped logical %d" % logical)
        n = min(length, lg + ln - logical)
        out += os.pread(fd, n, ph + logical - lg)
        logical += n
        length -= n
    return bytes(out)


def encrypted_ranges(size, mode, pct):
    if mode == 0x24:
        return [(0, size)]
    if mode == 0x26:
        return [(0, min(size, FIRST_LIMIT))]
    if mode == 0x25 and pct in PARTIAL_FACTORS:
        length = (size // 100) * PARTIAL_FACTORS[pct]
        count = 5 if pct == 50 else 3
        gap = length if pct == 50 else (size - 3 * length) // 2
        return [(i * (length + gap), length) for i in range(count)]
    return None


def subtract(intervals, a, b):
    out = []
    for x, y in intervals:
        if y <= a or x >= b:
            out.append((x, y))
            continue
        if x < a:
            out.append((x, a))
        if y > b:
            out.append((b, y))
    return out


dfd = os.open(dev, os.O_RDONLY)
for line in open(jobs, encoding="utf-8"):
    job = json.loads(line)
    rel = job["rel"]
    live = os.path.join(photos, rel + ".L0CK3D")
    try:
        lfd = os.open(live, os.O_RDONLY)
    except OSError:
        continue
    rep = {"rel": rel}
    tmp = None
    try:
        st = os.fstat(lfd)
        foot = os.pread(lfd, FOOTER, st.st_size - FOOTER)
        size = struct.unpack_from("<Q", foot, 580)[0]
        if size < min_size:
            continue
        mode, pct, crypto = foot[572], foot[573], foot[574]
        rep.update(size=size, mode=mode, pct=pct, crypto=crypto)
        if size != st.st_size - FOOTER:
            raise ValueError("footer size mismatch")
        ranges = encrypted_ranges(size, mode, pct)
        if ranges is None:
            raise ValueError("unknown mode")
        final = os.path.join(out_dir, rel)
        if os.path.lexists(final) or os.path.lexists(os.path.join(partial_dir, rel)):
            rep["status"] = "EXISTS"
            continue
        os.makedirs(os.path.dirname(final), exist_ok=True)
        tmp = final + ".tmp-extract"
        ofd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            for off in range(0, size, STEP):  # start from the live bytes (plaintext outside ranges)
                os.pwrite(ofd, os.pread(lfd, min(STEP, size - off), off), off)
            todo = [(o, o + n) for o, n in ranges]
            enc_total = sum(n for _o, n in ranges)
            same = 0
            for foff, dbytenr, eoff, nbytes in job["extents"]:
                lo, hi = foff, foff + nbytes
                for x, y in list(todo):
                    a, b = max(x, lo), min(y, hi)
                    if a >= b:
                        continue
                    for p in range(a, b, STEP):
                        q = min(b, p + STEP)
                        old = read_logical(dfd, dbytenr + eoff + (p - foff), q - p)
                        if old == os.pread(lfd, q - p, p):
                            same += q - p
                            continue
                        os.pwrite(ofd, old, p)
                        todo = subtract(todo, p, q)
            missing = sum(y - x for x, y in todo)
            cover = 1.0 - missing / enc_total if enc_total else 1.0
            for x, y in todo:  # zero bytes that are still ciphertext
                for p in range(x, y, STEP):
                    os.pwrite(ofd, bytes(min(STEP, y - p)), p)
            os.fsync(ofd)
        finally:
            os.close(ofd)
        with open(tmp, "rb") as f:
            head = f.read(16)
        magic = head[:3] == b"\xff\xd8\xff" or head[4:8] in (b"ftyp", b"wide", b"mdat", b"moov", b"free") or head[:4] in (b"RIFF", b"\x1aE\xdf\xa3")
        rep.update(cover=round(cover, 4), same_as_cipher=same, magic=magic)
        if missing == 0:
            os.rename(tmp, final)
            rep["status"] = "OK" if magic else "OK_UNVERIFIED"
        elif cover >= MIN_PARTIAL_COVER:
            dest = os.path.join(partial_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.rename(tmp, dest)
            rep["status"] = "PARTIAL"
        else:
            os.unlink(tmp)
            rep["status"] = "FAIL"
        tmp = None
    except Exception as e:
        rep["status"] = "ERR"
        rep["err"] = str(e)[:200]
    finally:
        os.close(lfd)
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        if "status" in rep:
            print(json.dumps(rep, ensure_ascii=False))
            sys.stdout.flush()
