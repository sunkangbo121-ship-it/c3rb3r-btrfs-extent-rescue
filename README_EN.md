# C3RB3R (.L0CK3D) rescue without the key: btrfs copy-on-write extent retention

[简体中文](README.md) (main write-up; the docs are in Chinese) | English

A de-identified post-incident record of a C3RB3R ransomware case on an Xpenology (bare-metal DSM 7.2.1) NAS. **Memory key recovery failed** — the encryptor had exited about 27 hours before response — but **most of the encrypted photo library was recovered without any key**, by exploiting how btrfs copy-on-write handles in-place partial overwrites.

> **Status: complete.** After merging and de-duplication, **17,893 of 24,142 files (74.1%), ~274 of 375 GiB (~73%)** were recovered without any key. Details in [docs/04](docs/04-results-and-limits.md); video repair in [docs/06](docs/06-video-repair.md).

## The idea in one paragraph

C3RB3R encrypts large files only partially and in place: mode `0x26` encrypts the first 1 MiB, mode `0x25` (pct=10) encrypts three 4% segments. On btrfs, the rewritten ranges go to new extents, but the untouched plaintext ranges keep referencing the **original** extent. btrfs frees an extent only when no byte of it is referenced, so the whole original extent — **including the bytes that are now encrypted in the live file** — stays allocated and intact (a "bookend" extent). Walk the current fs tree, take the references whose extent generation predates the attack, synthesize the full original extent (`file offset = foff − eoff`, extent byte 0, `disk_num_bytes`), map logical to physical via the chunk tree, read the encrypted ranges back from the raw LV and splice them with the live plaintext.

## Numbers (final)

| | |
|---|---|
| Encrypted files in the target folder | 24,142 (375 GiB): `0x26` 10,220 · `0x25` 7,197 · `0x24` 6,725 |
| RAM scan | 15.86 GiB via `/proc/kcore`, ~4.5e9 candidates, self-tested, 4 min 45 s → **NO_MATCH** |
| Bookend extent recovery | `0x26` **10,200 / 10,220** complete · `0x25` **7,071 / 7,197** complete + 102 partial · `0x24` 117 / 6,725 |
| Partial videos | lost `moov` recovered from the raw device, frames validated by NAL length framing, damaged seconds cut losslessly: **47 fully playable** (median ~98% duration kept); 35 replaced by Synology Photos' low-res transcode |
| Final (merged, de-duplicated) | **17,893 / 24,142 files, ~274 GiB**; the 6,249 lost are almost all ≤1 MiB whole-file-encrypted files |
| `btrfs restore` from old fs-tree roots | 2,442 files / 19.9 GiB with valid headers |
| Validation | header check on every file; 40 random images fully decoded (40/40); 8 sampled complete videos and every repaired video fully decoded track by track. **Format-level only — not original-SHA equality.** |

## Verified recovery paths

| Path | Status |
|---|---|
| Check whether the encryptor process is still alive (`ls -l /proc/*/exe \| grep deleted`) | verified — gone in this case |
| Whole-RAM capture via `/proc/kcore` → LiME over SSH + self-tested key scan | method verified; no key in this case |
| Footer census to set expectations by mode | verified, do this first |
| Stop every package writing to the volume (`/usr/syno/bin/synopkg stop`, full path) | verified |
| Run `btrfs restore` on the underlying LV `/dev/mapper/vgN-volume_N`, not the mounted `cachedev_N` | verified working |
| `btrfs-find-root -a -o SUBVOL_ID` + `btrfs restore -f ROOT_BYTENR` when the subvolume pointer in the old root tree is gone | verified working (2,442 files) |
| **Bookend extent synthesis** (`walk_tree.py` → `make_jobs2.py` → `extract_jobs.py`) for `0x25`/`0x26` | **verified working, close to 100%** |
| Orphan-leaf references (`parse_leaves.py`) for `0x24` | partially working |
| soimy's published session key | not applicable (different session marker `0b5c8e4c`) |
| `btrfs restore -t <old root tree> -r SUBVOL_ID` | 0 files |

Step-by-step commands: [docs/00-runbook.md](docs/00-runbook.md).

## What this does not claim

- No key was recovered; no decryptor is included.
- Recovered files are not proven bit-identical to the originals; btrfs csum-tree verification has not been done yet.
- `0x24` (whole-file) small files are mostly lost; for those, a valid header is not proof of content.
- The method depends on btrfs CoW, free space on the volume, and stopping writers quickly. It does not apply to ext4 or NOCOW files.

## Licence and credits

Code in `tools/` is MIT; documentation is CC BY 4.0. Footer format and segment rules follow [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue); soimy's `decrypt_copy.py` is not included (only a one-line diff is described in docs/02). Structure and the "self-test before declaring NO_MATCH" principle follow [lllong1377/c3rb3r-never-rebooted-still-no-key](https://github.com/lllong1377/c3rb3r-never-rebooted-still-no-key).
