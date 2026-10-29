"""Rebuild original files from pre-attack extents + plaintext ranges of the live .L0CK3D file.

usage (root on NAS): python3 - DEVICE CHUNKMAP TARGET_ROOT JOBS OUT_DIR PARTIAL_DIR < extract_jobs.py > report.jsonl
  DEVICE      underlying LV, e.g. /dev/mapper/vg1-volume_1 (opened O_RDONLY)
  TARGET_ROOT live directory holding the *.L0CK3D files, e.g. /volume1/homes/USER/Photos (read only)
  OUT_DIR / PARTIAL_DIR must be on ANOTHER volume, e.g. /volume2/rescue_extent/{ok,partial}
Reads the raw device and live files only; writes new files under OUT_DIR / PARTIAL_DIR with O_EXCL,
never overwriting. Files larger than MAX_SIZE are reported as ERR "BIG" (needs a streaming pass).
"""
import bisect, json, os, struct, sys

dev, chunkmap, target_root, jobs, out_dir, partial_dir = sys.argv[1:7]
FOOTER = 588
FIRST_LIMIT = 1 << 20
PARTIAL_FACTORS = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12, 40: 14, 50: 10, 60: 20, 70: 23, 80: 27}
MIN_PARTIAL_COVER = 0.5
MAX_SIZE = 1536 << 20  # larger files need a streaming pass

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


def magic_ok(head):
    return (head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n" or head[4:8] in (b"ftyp", b"wide", b"mdat", b"moov", b"free")
            or head[:2] == b"BM" or head[:4] in (b"RIFF", b"\x30\x26\xb2\x75", b"II*\x00", b"MM\x00*", b"\x1aE\xdf\xa3", b"8BPS", b"%PDF")
            or head[:6] in (b"GIF87a", b"GIF89a") or head[:1] == b"\x47" or head[:4] == b"\x00\x00\x01\xba")


def write_new(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


dfd = os.open(dev, os.O_RDONLY)
for line in open(jobs, encoding="utf-8"):
    job = json.loads(line)
    rel = job["rel"]
    rep = {"rel": rel}
    try:
        live = os.path.join(target_root, rel + ".L0CK3D")
        with open(live, "rb") as f:
            st = os.fstat(f.fileno())
            f.seek(-FOOTER, 2)
            foot = f.read(FOOTER)
            size = struct.unpack_from("<Q", foot, 580)[0]
            if size > MAX_SIZE:
                raise ValueError("BIG %d" % size)
            mode, pct, crypto = foot[572], foot[573], foot[574]
            if size != st.st_size - FOOTER:
                raise ValueError("footer size mismatch")
            f.seek(0)
            data = bytearray(f.read(size))
        rep.update(size=size, mode=mode, pct=pct, crypto=crypto)
        ranges = encrypted_ranges(size, mode, pct)
        if ranges is None:
            raise ValueError("unknown mode")
        need = bytearray(size)  # 1 = byte still encrypted / missing
        for off, ln in ranges:
            need[off:off + ln] = b"\x01" * ln
        enc_total = sum(ln for _o, ln in ranges)
        same_as_cipher = 0
        filled = 0
        for foff, dbytenr, eoff, nbytes in job["extents"]:
            lo, hi = max(foff, 0), min(foff + nbytes, size)
            for off, ln in ranges:
                a, b = max(lo, off), min(hi, off + ln)
                if a >= b:
                    continue
                # fill only bytes no earlier (more exact) extent has already supplied
                pos = need.find(1, a, b)
                while pos != -1:
                    end = need.find(0, pos, b)
                    end = b if end == -1 else end
                    old = read_logical(dfd, dbytenr + eoff + (pos - foff), end - pos)
                    if old == bytes(data[pos:end]):
                        same_as_cipher += end - pos
                    else:
                        data[pos:end] = old
                        need[pos:end] = bytes(end - pos)
                        filled += end - pos
                    pos = need.find(1, end, b)
        missing = need.count(1)
        cover = 1.0 - missing / enc_total if enc_total else 1.0
        rep.update(cover=round(cover, 4), same_as_cipher=same_as_cipher, magic=magic_ok(bytes(data[:16])))
        if missing == 0 and (rep["magic"] or mode in (0x25, 0x26)):
            # partial-mode files reuse still-referenced extents, so a missing magic is only a format gap
            write_new(os.path.join(out_dir, rel), bytes(data))
            rep["status"] = "OK" if rep["magic"] else "OK_UNVERIFIED"
        elif cover >= MIN_PARTIAL_COVER and rep["magic"]:
            pos = need.find(1)  # zero still-encrypted runs so viewers see gaps, not noise
            while pos != -1:
                end = need.find(0, pos)
                end = size if end == -1 else end
                data[pos:end] = bytes(end - pos)
                pos = need.find(1, end)
            write_new(os.path.join(partial_dir, rel), bytes(data))
            rep["status"] = "PARTIAL"
        else:
            rep["status"] = "FAIL"
    except FileExistsError:
        rep["status"] = "EXISTS"
    except Exception as e:  # keep going; report per file
        rep["status"] = "ERR"
        rep["err"] = str(e)[:200]
    print(json.dumps(rep, ensure_ascii=False))
    sys.stdout.flush()
