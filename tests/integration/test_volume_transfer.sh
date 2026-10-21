#!/bin/bash
# A real SSH round trip on isolated volumes; no machine or workload is stopped.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh"
source "$HERE/../lib/machine.sh"
ROOT="$(cd "$HERE/../.." && pwd)"
MACHINE=$(guest_machine) || exit 1
SCRATCH=$(mktemp -d) || exit 1
PREFIX="s1-test-transfer-$(date +%s)-$$"

cleanup() {
    local privilege
    for privilege in '' 'sudo -n '; do
        # Only the names this process allocated. Never use prune or --all.
        podman machine ssh "$MACHINE" "${privilege}podman volume rm $PREFIX-src $PREFIX-dst $PREFIX-restore" >/dev/null 2>&1 || true
    done
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

roundtrip() {
    local mode="$1" privilege="$2" src="$PREFIX-src" dst="$PREFIX-dst" result rc
    local namespace='podman unshare '
    [ "$mode" != rootful ] || namespace='sudo -n '
    local archive="$SCRATCH/$mode volume.tar"
    podman machine ssh "$MACHINE" "${privilege}podman volume create --label purpose=s1-transfer-test $src" >/dev/null || return 1
    podman machine ssh "$MACHINE" "${privilege}podman volume create --label purpose=s1-transfer-test $dst" >/dev/null || return 1
    # unshare gives a rootless podman the namespace needed to mount its volume.
    podman machine ssh "$MACHINE" "${namespace}bash -s -- $src" <<'GUEST' || return 1
set -e
mount=$(podman volume mount "$1")
mkdir -p "$mount/nested"
printf 'S1_VOLUME_PAYLOAD\000\377\n' > "$mount/nested/marker"
chmod 640 "$mount/nested/marker"
ln -s nested/marker "$mount/link"
GUEST
    assert_ok "$mode exports over SSH" "$ROOT/scripts/podman-volume-transfer.sh" \
        --machine "$MACHINE" "--$mode" export "$src" "$archive"
    assert_ok "$mode imports over SSH" "$ROOT/scripts/podman-volume-transfer.sh" \
        --machine "$MACHINE" "--$mode" import "$dst" "$archive"
    result=$(podman machine ssh "$MACHINE" "${namespace}bash -s -- $src $dst" <<'GUEST'
set -e
src=$(podman volume mount "$1")
dst=$(podman volume mount "$2")
cmp "$src/nested/marker" "$dst/nested/marker"
test "$(stat -c '%a:%u:%g' "$src/nested/marker")" = "$(stat -c '%a:%u:%g' "$dst/nested/marker")"
test "$(readlink "$dst/link")" = nested/marker
echo PAYLOAD_OK
GUEST
    ); rc=$?
    assert_eq 0 "$rc" "$mode payload, ownership, permissions and symlink match"
    assert_contains "$result" PAYLOAD_OK "$mode data reached the target volume"

    # Exercise deploy.sh's real guest restore too, independently of the helper.
    local backup="$SCRATCH/$mode-restore" restore_volume="$PREFIX-restore"
    mkdir -p "$backup/volumes" "$backup/containers"
    for list in images.txt pods.txt running.txt expected.txt; do : > "$backup/$list"; done
    printf '%s\n' "$restore_volume" > "$backup/volumes.txt"
    cp "$archive" "$backup/volumes/$restore_volume.tar"
    printf 'set -e\npodman volume create %s\n' "$restore_volume" > "$backup/volumes-create.sh"
    result=$({ printf 'DIR=%q\n' "$backup"
               awk "/^RESTORE_GUEST_SCRIPT='/{f=1;next} f&&/^'\$/{exit} f" "$ROOT/deploy.sh"
             } | podman machine ssh "$MACHINE" "${privilege}bash -s" 2>&1); rc=$?
    assert_eq 0 "$rc" "$mode deploy guest restore completes"
    assert_contains "$result" RESTORE_OK "$mode deploy guest confirms completion"
    result=$(podman machine ssh "$MACHINE" "${namespace}bash -s -- $src $restore_volume" <<'GUEST'
set -e
src=$(podman volume mount "$1")
dst=$(podman volume mount "$2")
cmp "$src/nested/marker" "$dst/nested/marker"
echo PAYLOAD_OK
GUEST
    ); rc=$?
    assert_eq 0 "$rc" "$mode deploy restore preserves binary payload"
    assert_contains "$result" PAYLOAD_OK "$mode deploy target has the data"

    # The complete host entry point must accept a successful restore too. This
    # catches a deletion gate that always rejects, while --keep-backup retains
    # the fixture until this test's cleanup.
    podman machine ssh "$MACHINE" "${privilege}podman volume rm $restore_volume" >/dev/null || return 1
    printf '{}\n' > "$backup/manifest.json"
    if [ "$mode" = rootful ]; then echo true; else echo false; fi > "$backup/rootful.txt"
    result=$(PODMAN_MACHINE_NAME="$MACHINE" "$ROOT/deploy.sh" --restore "$backup" --keep-backup 2>&1); rc=$?
    assert_eq 0 "$rc" "$mode host restore and verification complete"
    assert_contains "$result" 'Everything in the backup is back' "$mode host confirms verified completion"
    assert_file_exists "$backup/volumes/$restore_volume.tar" "$mode --keep-backup retains the source archive"
}

test_rootless_volume_transfer() { roundtrip rootless '' || t_fail 'rootless fixture setup'; }
test_rootful_volume_transfer() { roundtrip rootful 'sudo -n ' || t_fail 'rootful fixture setup'; }

run_tests
