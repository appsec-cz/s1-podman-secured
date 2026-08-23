#!/bin/bash
#
# Layer 2 - the built image, without booting it. Runs on macOS, needs nothing but
# python3 and zstd.
#
# This layer exists because of one specific failure mode: a build that reports
# success and produces an image that cannot boot. The bootloader has to agree
# with the filesystem it is supposed to find, and that is checkable statically.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

IMAGE="${TEST_IMAGE_PATH:-}"
if [ -z "$IMAGE" ]; then
    IMAGE=$(find "$ROOT/output" -maxdepth 1 -name 'podman-debian*.raw.zst' -type f 2>/dev/null | head -1)
fi

WORK="${TMPDIR:-/tmp}/s1-image-test.$$"
RAW_HEAD="$WORK/head.bin"
# 220 MB covers the GPT, the whole ESP and the start of the root filesystem,
# which is everything this layer needs. Decompressing 10 GB would not.
HEAD_BYTES=$((220 * 1024 * 1024))

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

prepare() {
    mkdir -p "$WORK"
    case "$IMAGE" in
        *.zst) zstd -dc "$IMAGE" 2>/dev/null | head -c "$HEAD_BYTES" > "$RAW_HEAD" ;;
        *)     head -c "$HEAD_BYTES" "$IMAGE" > "$RAW_HEAD" ;;
    esac
    [ -s "$RAW_HEAD" ]
}

# Emits: partnum offset size partuuid fstype  (one line per partition)
probe_partitions() {
    python3 - "$RAW_HEAD" <<'PY'
import struct, sys, uuid

path = sys.argv[1]
with open(path, 'rb') as f:
    f.seek(512)
    hdr = f.read(92)
    if hdr[:8] != b'EFI PART':
        sys.exit('no GPT header')
    part_lba, num, sz = struct.unpack('<Q', hdr[72:80])[0], struct.unpack('<I', hdr[80:84])[0], struct.unpack('<I', hdr[84:88])[0]
    f.seek(part_lba * 512)
    entries = [f.read(sz) for _ in range(num)]

    for i, e in enumerate(entries, start=1):
        if e[:16] == b'\x00' * 16:
            continue
        guid = uuid.UUID(bytes_le=e[16:32])
        first = struct.unpack('<Q', e[32:40])[0]
        last = struct.unpack('<Q', e[40:48])[0]
        off = first * 512
        f.seek(off)
        f.seek(off + 65600); btrfs_magic = f.read(8)
        f.seek(off + 1080);  ext_magic = f.read(2)
        f.seek(off + 0x36);  fat = f.read(5)
        if btrfs_magic == b'_BHRfS_M':
            fstype = 'btrfs'
        elif ext_magic == b'\x53\xef':
            fstype = 'ext4'
        elif fat.startswith(b'FAT'):
            fstype = 'vfat'
        else:
            fstype = 'unknown'
        print(i, off, (last - first + 1) * 512, guid, fstype)
PY
}

btrfs_uuid() {
    local offset="$1"
    python3 - "$RAW_HEAD" "$offset" <<'PY'
import sys, uuid
path, off = sys.argv[1], int(sys.argv[2])
with open(path, 'rb') as f:
    f.seek(off + 65568)
    print(uuid.UUID(bytes=f.read(16)))
PY
}

# The ESP is FAT, so the stub grub.cfg sits there as plain bytes.
esp_grub_cfg() {
    local offset="$1" size="$2"
    python3 - "$RAW_HEAD" "$offset" "$size" <<'PY'
import re, sys
path, off, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with open(path, 'rb') as f:
    f.seek(off)
    data = f.read(size)
# 'search.fs_uuid' also appears inside grubaa64.efi as a command name, so
# require the UUID argument to pin the match to the stub config itself.
m = re.search(rb'search\.fs_uuid\s+[0-9a-f-]{36}[^\x00]{0,80}', data)
print(m.group().decode('utf-8', 'replace') if m else '')
PY
}

# ---------------------------------------------------------------------------

test_image_present() {
    t_pass "image found: $(basename "$IMAGE")"
    t_info "$(du -h "$IMAGE" | awk '{print $1}'), built $(date -r "$IMAGE" '+%Y-%m-%d %H:%M')"
    t_pass "image decompresses"
}

test_partition_layout() {
    local parts
    parts=$(probe_partitions)
    assert_matches "$parts" "vfat" "an EFI system partition exists"
    assert_matches "$parts" "btrfs" "the root filesystem is btrfs"
    assert_not_contains "$parts" "ext4" "no ext4 partition is left after conversion"

    local rootnum
    rootnum=$(printf '%s' "$parts" | awk '$5=="btrfs" {print $1}')
    assert_eq "2" "$rootnum" "the root filesystem is partition 2 after virt-resize"
}

test_bootloader_points_at_the_root_filesystem() {
    # The failure this catches: the EFI stub keeps searching for the UUID the
    # filesystem had before the btrfs conversion, GRUB never finds /boot/grub,
    # and the VM sits at a rescue prompt with no console output at all.
    local parts esp_off esp_size root_off
    parts=$(probe_partitions)
    esp_off=$(printf '%s' "$parts" | awk '$5=="vfat" {print $2}')
    esp_size=$(printf '%s' "$parts" | awk '$5=="vfat" {print $3}')
    root_off=$(printf '%s' "$parts" | awk '$5=="btrfs" {print $2}')

    if [ -z "$esp_off" ] || [ -z "$root_off" ]; then
        t_fail "bootloader check" "could not locate both partitions"
        return
    fi

    local fs_uuid stub
    fs_uuid=$(btrfs_uuid "$root_off")
    stub=$(esp_grub_cfg "$esp_off" "$esp_size")

    assert_matches "$fs_uuid" '^[0-9a-f-]{36}$' "btrfs filesystem has a UUID ($fs_uuid)"
    assert_contains "$stub" "search.fs_uuid" "the ESP carries a GRUB stub config"
    assert_contains "$stub" "$fs_uuid" "the ESP stub searches for the btrfs UUID"
}

test_image_size_is_sane() {
    local bytes
    bytes=$(stat -f %z "$IMAGE" 2>/dev/null || stat -c %s "$IMAGE")
    if [ "$bytes" -lt $((300 * 1024 * 1024)) ]; then
        t_fail "image size" "only $((bytes / 1024 / 1024)) MB - the build probably produced a stub"
    elif [ "$bytes" -gt $((4 * 1024 * 1024 * 1024)) ]; then
        t_fail "image size" "$((bytes / 1024 / 1024)) MB is far larger than expected"
    else
        t_pass "image size is plausible ($((bytes / 1024 / 1024)) MB compressed)"
    fi
}

test_checksum_matches() {
    local sum_file="${IMAGE}.sha256"
    if [ ! -f "$sum_file" ]; then
        t_skip "checksum matches the image" "no ${sum_file##*/}"
        return
    fi
    local expected actual
    expected=$(awk '{print $1}' "$sum_file")
    actual=$(shasum -a 256 "$IMAGE" | awk '{print $1}')
    assert_eq "$expected" "$actual" "sha256 matches the recorded checksum"
}

# Unpack before the first test: run_tests calls test functions in alphabetical
# order, so no test can rely on another having run first.
if [ -z "$IMAGE" ] || [ ! -f "$IMAGE" ]; then
    printf 'ERROR: no image to test. Build one, or set TEST_IMAGE_PATH.\n' >&2
    printf '       looked for %s/output/podman-debian*.raw.zst\n' "$ROOT" >&2
    exit 1
fi
if ! prepare; then
    printf 'ERROR: could not read %s\n' "$IMAGE" >&2
    exit 1
fi

run_tests
