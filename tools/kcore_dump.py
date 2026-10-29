"""Stream physical RAM from /proc/kcore to stdout as LiME segments (stdlib only, Python 3.8).

Usage: python3 - [--list] < kcore_dump.py   (run as root)
Only PT_LOAD segments of the direct map (KCORE_RAM, p_paddr valid) are read.
Unreadable chunks are zero-filled and reported on stderr; nothing is written to disk.
"""
import collections, os, struct, sys

LIME_MAGIC, LIME_VERSION = 0x4C694D45, 1
CHUNK = 4 << 20
PAGE = 4096
NO_PADDR = 0xFFFFFFFFFFFFFFFF


def ram_segments(fd):
    hdr = os.pread(fd, 64, 0)
    if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
        sys.exit("kcore is not ELF64")
    phoff, = struct.unpack_from("<Q", hdr, 32)
    phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
    loads = []
    table = os.pread(fd, phentsize * phnum, phoff)
    for i in range(phnum):
        p_type, _flags, off, vaddr, paddr, filesz, _memsz, _align = struct.unpack_from("<IIQQQQQQ", table, i * phentsize)
        if p_type == 1 and paddr != NO_PADDR and filesz:
            loads.append((off, vaddr, paddr, filesz))
    # Direct-map RAM segments all share one vaddr-paddr delta; the kernel text segment does not.
    delta = collections.Counter(v - p for _o, v, p, _s in loads).most_common(1)[0][0]
    return sorted((p, s, o) for o, v, p, s in loads if v - p == delta)


def main():
    fd = os.open("/proc/kcore", os.O_RDONLY)
    segs = ram_segments(fd)
    total = sum(s for _p, s, _o in segs)
    for p, s, _o in segs:
        sys.stderr.write("RAM %#014x-%#014x %8.1f MiB\n" % (p, p + s - 1, s / 2**20))
    sys.stderr.write("TOTAL %.2f GiB in %d segments\n" % (total / 2**30, len(segs)))
    if "--list" in sys.argv:
        return
    out = sys.stdout.buffer
    done = bad = 0
    for paddr, size, off in segs:
        out.write(struct.pack("<IIQQQ", LIME_MAGIC, LIME_VERSION, paddr, paddr + size - 1, 0))
        pos = 0
        while pos < size:
            n = min(CHUNK, size - pos)
            try:
                data = os.pread(fd, n, off + pos)
                if len(data) != n:
                    raise OSError("short read")
            except OSError:
                parts = []
                for p in range(0, n, PAGE):
                    m = min(PAGE, n - p)
                    try:
                        page = os.pread(fd, m, off + pos + p)
                    except OSError:
                        page = b""
                    if len(page) != m:
                        bad += 1
                        sys.stderr.write("HOLE %#x\n" % (paddr + pos + p))
                        page = b"\0" * m
                    parts.append(page)
                data = b"".join(parts)
            out.write(data)
            pos += n
            done += n
            if done % (512 << 20) < CHUNK:
                sys.stderr.write("progress %.2f / %.2f GiB\n" % (done / 2**30, total / 2**30))
                sys.stderr.flush()
    out.flush()
    sys.stderr.write("DONE bytes=%d unreadable_pages=%d\n" % (done, bad))


main()
