#!/bin/sh
# Restore one directory from OLD fs-tree roots of a btrfs subvolume into ANOTHER volume.
#
# usage (root on NAS):
#   sh btrfs_restore_run.sh LV_DEVICE OUT_DIR PATH_REGEX ROOT_BYTENR [ROOT_BYTENR ...]
# example:
#   sh btrfs_restore_run.sh /dev/mapper/vg1-volume_1 /volume2/rescue_restore \
#       '^/(|USER(|/Photos(|/.*)))$' ROOT_BYTENR_1 ROOT_BYTENR_2 ROOT_BYTENR_3
#
# - LV_DEVICE is the underlying LV (/dev/mapper/vgN-volume_N), NOT the mounted
#   /dev/mapper/cachedev_N: btrfs restore refuses a mounted device, and it only
#   reads from LV_DEVICE.
# - ROOT_BYTENR are fs-tree root blocks of the subvolume found with
#   `btrfs-find-root -a -o SUBVOL_ID LV_DEVICE` (dry-run each with -D first).
# - OUT_DIR must be on a different volume and must not exist yet.
# - -i ignores errors, -m restores owner/mode/times. Files already present in OUT_DIR
#   are not overwritten by later roots (no -o), so list the best root first.
set -u
[ $# -ge 4 ] || { echo "usage: btrfs_restore_run.sh LV_DEVICE OUT_DIR PATH_REGEX ROOT_BYTENR [ROOT_BYTENR ...]" >&2; exit 2; }
DEV=$1; OUT=$2; REGEX=$3; shift 3
LOG="$OUT.log"
mkdir -m 700 "$OUT" || exit 1
df -h "$OUT" > "$LOG"
for b in "$@"; do
  echo "=== root $b start $(date)" >> "$LOG"
  nice -n 10 btrfs restore -v -i -m -f "$b" --path-regex "$REGEX" \
    "$DEV" "$OUT" 2>&1 | grep -v 'parent transid verify failed' >> "$LOG"
  echo "=== root $b done $(date)" >> "$LOG"
done
echo ALL_DONE >> "$LOG"
