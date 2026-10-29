"""Walk the sample tables of a MOV/MP4 and validate each video sample's NAL length framing.

usage: python3 movsamples.py FILE            -> prints first bad sample (file offset) per track
       import: samples(path) -> list of (track_kind, offset, size); nal_ok(buf) -> bool
Video samples (avc1/hvc1/hev1) are length-prefixed NAL units; the lengths must tile the sample exactly.
"""
import struct, sys


def atoms(buf, start, end):
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack_from(">I4s", buf, pos)
        hdr = 8
        if size == 1:
            size = struct.unpack_from(">Q", buf, pos + 8)[0]
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            return
        yield typ, pos + hdr, pos + size
        pos += size


def find(buf, start, end, path):
    for typ, s, e in atoms(buf, start, end):
        if typ == path[0]:
            if len(path) == 1:
                yield s, e
            else:
                yield from find(buf, s, e, path[1:])


def top_level(f, size):
    pos = 0
    while pos + 8 <= size:
        f.seek(pos)
        h = f.read(16)
        sz, typ = struct.unpack(">I4s", h[:8])
        if sz == 1:
            sz = struct.unpack(">Q", h[8:16])[0]
        if sz < 8:
            return
        yield typ, pos, sz
        pos += sz


def samples(path):
    import os
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        moov = None
        for typ, pos, sz in top_level(f, size):
            if typ == b"moov":
                f.seek(pos)
                moov = f.read(sz)
        if moov is None:
            raise ValueError("no moov")
    out = []
    for ts, te in find(moov, 8, len(moov), [b"trak"]):
        kind = "other"
        for s, e in find(moov, ts, te, [b"mdia", b"hdlr"]):
            kind = moov[s + 8:s + 12].decode("latin1")
        codec = b""
        stbl = list(find(moov, ts, te, [b"mdia", b"minf", b"stbl"]))
        if not stbl:
            continue
        s0, e0 = stbl[0]
        for s, e in find(moov, s0, e0, [b"stsd"]):
            codec = moov[s + 12:s + 16]
        sizes = []
        for s, e in find(moov, s0, e0, [b"stsz"]):
            fixed, n = struct.unpack_from(">II", moov, s + 4)
            sizes = [fixed] * n if fixed else list(struct.unpack_from(">%dI" % n, moov, s + 12))
        chunks = []
        for s, e in find(moov, s0, e0, [b"stco"]):
            n, = struct.unpack_from(">I", moov, s + 4)
            chunks = list(struct.unpack_from(">%dI" % n, moov, s + 8))
        for s, e in find(moov, s0, e0, [b"co64"]):
            n, = struct.unpack_from(">I", moov, s + 4)
            chunks = list(struct.unpack_from(">%dQ" % n, moov, s + 8))
        stsc = []
        for s, e in find(moov, s0, e0, [b"stsc"]):
            n, = struct.unpack_from(">I", moov, s + 4)
            stsc = [struct.unpack_from(">III", moov, s + 8 + 12 * i) for i in range(n)]
        si = 0
        for ci, off in enumerate(chunks, 1):
            per = 0
            for first, spc, _d in stsc:
                if first <= ci:
                    per = spc
            for _ in range(per):
                if si >= len(sizes):
                    break
                out.append((kind, codec, off, sizes[si]))
                off += sizes[si]
                si += 1
    return out


def nal_ok(buf):
    pos = 0
    while pos < len(buf):
        if pos + 4 > len(buf):
            return False
        n, = struct.unpack_from(">I", buf, pos)
        if n == 0 or pos + 4 + n > len(buf) or buf[pos + 4] & 0x80:
            return False
        pos += 4 + n
    return True


if __name__ == "__main__":
    p = sys.argv[1]
    sm = samples(p)
    with open(p, "rb") as f:
        bad = {}
        total = {}
        for kind, codec, off, sz in sm:
            total[kind] = total.get(kind, 0) + 1
            if kind != "vide" or codec not in (b"avc1", b"hvc1", b"hev1"):
                continue
            f.seek(off)
            if not nal_ok(f.read(sz)) and kind not in bad:
                bad[kind] = (off, sz)
    print("samples per track:", total)
    print("first bad video sample (offset,size):", bad.get("vide"))


def video_timeline(path):
    """[(offset, size, seconds, is_sync)] for the first avc1/hvc1/hev1 track, in decode order."""
    import os
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        moov = None
        for typ, pos, sz in top_level(f, size):
            if typ == b"moov":
                f.seek(pos)
                moov = f.read(sz)
    for ts, te in find(moov, 8, len(moov), [b"trak"]):
        stbl = list(find(moov, ts, te, [b"mdia", b"minf", b"stbl"]))
        if not stbl:
            continue
        s0, e0 = stbl[0]
        codec = b""
        for s, e in find(moov, s0, e0, [b"stsd"]):
            codec = moov[s + 12:s + 16]
        if codec not in (b"avc1", b"hvc1", b"hev1"):
            continue
        timescale = 600
        for s, e in find(moov, ts, te, [b"mdia", b"mdhd"]):
            timescale = struct.unpack_from(">I", moov, s + (20 if moov[s] == 1 else 12))[0]
        deltas = []
        for s, e in find(moov, s0, e0, [b"stts"]):
            n, = struct.unpack_from(">I", moov, s + 4)
            for i in range(n):
                cnt, d = struct.unpack_from(">II", moov, s + 8 + 8 * i)
                deltas += [d] * cnt
        sync = None
        for s, e in find(moov, s0, e0, [b"stss"]):
            n, = struct.unpack_from(">I", moov, s + 4)
            sync = set(struct.unpack_from(">%dI" % n, moov, s + 8))
        offs = [(o, sz) for k, c, o, sz in samples(path) if k == "vide" and c == codec]
        out, t = [], 0
        for i, (o, sz) in enumerate(offs):
            out.append((o, sz, t / timescale, sync is None or (i + 1) in sync))
            t += deltas[i] if i < len(deltas) else (deltas[-1] if deltas else 0)
        return out
    return []


def bad_time_ranges(path, margin=0.5):
    """Merged [start, end) seconds to drop: from just before each bad frame to the next good sync frame."""
    tl = video_timeline(path)
    if not tl:
        return [], 0.0
    with open(path, "rb") as f:
        bad = []
        for o, sz, t, _s in tl:
            f.seek(o)
            bad.append(not nal_ok(f.read(sz)))
    total = tl[-1][2]
    ranges, i = [], 0
    while i < len(tl):
        if not bad[i]:
            i += 1
            continue
        start = max(0.0, tl[i][2] - margin)
        j = i
        while j < len(tl) and (bad[j] or not tl[j][3]):
            j += 1  # skip bad frames and the non-sync frames that depend on them
        end = tl[j][2] if j < len(tl) else total + 1.0
        if ranges and start <= ranges[-1][1]:
            ranges[-1][1] = end
        else:
            ranges.append([start, end])
        i = j
    return ranges, total


def segment_time_ranges(path, size=None, pct_factor=4):
    """Time spans of the three C3RB3R 0x25 (pct=10) encrypted byte segments, each widened to whole GOPs."""
    import os
    size = size or os.path.getsize(path)
    tl = video_timeline(path)
    if not tl:
        return []
    L = (size // 100) * pct_factor
    gap = (size - 3 * L) // 2
    out = []
    for i in range(3):
        a, b = i * (L + gap), i * (L + gap) + L
        idx = [k for k, (o, sz, t, s) in enumerate(tl) if o + sz > a and o < b]
        if not idx:
            continue
        j = idx[-1] + 1
        while j < len(tl) and not tl[j][3]:
            j += 1
        end = tl[j][2] if j < len(tl) else tl[-1][2] + 1.0
        out.append((max(0.0, tl[idx[0]][2] - 0.5), end))
    return out
