"""Build a synthetic LiME image with ONE planted master key, to prove keyscan can find it.

usage: python3 make_selftest.py OUT_DIR [SIZE_MIB]          (needs: pip install cryptography)
Writes into OUT_DIR (must not exist):
  planted.lime   single-segment LiME image of random bytes with iv16|key32 planted at a random,
                 deliberately unaligned offset
  blank.lime     the same random bytes without the key (negative control)
  footers.bin    2 x 48-byte records: one wrapped with the planted master, one with an unrelated
                 master (must never hit)
  expect.txt     the expected HIT offset (file offset of key32 inside planted.lime)
Then:
  keyscan OUT_DIR/planted.lime OUT_DIR/footers.bin 4   -> exactly 1 HIT, footer=0, off=<expect>
  keyscan OUT_DIR/blank.lime   OUT_DIR/footers.bin 4   -> 0 HIT
Everything is synthetic; no real key material is involved.
"""
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LIME_MAGIC = 0x4C694D45


def wrap(master, rec):
    iv, key = master[:16], master[16:48]
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(rec) + enc.finalize()


def record():
    nonce = os.urandom(8)
    return os.urandom(32) + nonce + nonce        # file_key32 | nonce8 | nonce8


def lime(data, paddr=0x100000):
    return struct.pack("<IIQQQ", LIME_MAGIC, 1, paddr, paddr + len(data) - 1, 0) + data


def main():
    out = sys.argv[1]
    size = int(sys.argv[2]) << 20 if len(sys.argv) > 2 else 8 << 20
    os.makedirs(out)
    master, decoy = os.urandom(48), os.urandom(48)
    footers = wrap(master, record()) + wrap(decoy, record())
    body = bytearray(os.urandom(size))
    off = int.from_bytes(os.urandom(4), "little") % (size - 4096) + 1024
    off |= 1                                      # force an odd (unaligned) offset
    body_blank = bytes(body)
    body[off:off + 48] = master                   # iv16 | key32
    with open(os.path.join(out, "planted.lime"), "xb") as f:
        f.write(lime(bytes(body)))
    with open(os.path.join(out, "blank.lime"), "xb") as f:
        f.write(lime(body_blank))
    with open(os.path.join(out, "footers.bin"), "xb") as f:
        f.write(footers)
    hit = 32 + off + 16                           # LiME header + iv16
    with open(os.path.join(out, "expect.txt"), "x") as f:
        f.write("%d\n" % hit)
    print("expect exactly one HIT footer=0 off=%d in planted.lime, none in blank.lime" % hit)


main()
