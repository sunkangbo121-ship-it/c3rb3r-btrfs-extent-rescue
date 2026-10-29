"""Classify restored files: real media header, C3RB3R footer, all-zero, or unknown.

Usage on NAS: sudo python3 - ROOT [MARKER_HEX] < verify_restored.py > report.tsv
MARKER_HEX = 4-byte session marker at footer[568:572] (default 0b5c8e4c, this incident).
Skips @eaDir and the ransom note read-me3.txt. Read-only. Header check only: OK_* means the
first bytes look like the named format, NOT that the file is complete or bit-identical.
"""
import os, sys

MARKER = bytes.fromhex(sys.argv[2] if len(sys.argv) > 2 else "0b5c8e4c")


def kind(head):
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"heim", b"heis"):
            return "heic"
        if brand == b"qt  ":
            return "mov"
        return "mp4"
    if head[4:8] in (b"wide", b"mdat", b"moov", b"free", b"skip"):
        return "mov"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] == b"\x30\x26\xb2\x75":
        return "wmv"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    return None


root = sys.argv[1]
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d != "@eaDir"]
    for name in filenames:
        if name == "read-me3.txt":
            continue
        path = os.path.join(dirpath, name)
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                head = f.read(64)
                tail = b""
                if size >= 588:
                    f.seek(-588, 2)
                    tail = f.read(588)
                f.seek(size // 2)
                mid = f.read(4096)
        except OSError as e:
            print("ERR\t%d\t%s\t%s" % (0, path, e))
            continue
        if size == 0:
            status = "EMPTY"
        elif tail[568:572] == MARKER:
            status = "ENCRYPTED"
        elif head.count(0) == len(head) and mid.count(0) == len(mid):
            status = "ZEROS"
        else:
            k = kind(head)
            status = "OK_" + k if k else "UNKNOWN"
        print("%s\t%d\t%s" % (status, size, os.path.relpath(path, root)))
