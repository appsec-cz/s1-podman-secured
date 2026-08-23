#!/bin/bash
#
# Layer 5 - podman's own system test suite, run inside the machine.
#
# The point is not to test podman: Debian already does that. The point is that
# these tests exercise podman against *our* configuration - btrfs storage, crun,
# netavark, journald logs, rootless subuid ranges, cgroup delegation - and they
# cover far more of that surface than anything written by hand here.
#
# DESTRUCTIVE. Upstream says it plainly: the suite wipes container storage. It
# therefore runs on a throwaway machine, never on one someone works on.
#
# Usage:
#   ./tests/podman-system/run.sh                 # whole vendored suite
#   ./tests/podman-system/run.sh 500 035         # only matching files
#   PODMAN_SYSTEM_ROOTFUL=1 ./tests/podman-system/run.sh
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

VENDOR="$HERE/vendor"
REMOTE_DIR="/home/core/podman-system-tests"
KEEP_MACHINE="${KEEP_MACHINE:-0}"
ROOTFUL="${PODMAN_SYSTEM_ROOTFUL:-0}"

if [ ! -d "$VENDOR" ] || [ -z "$(ls -A "$VENDOR" 2>/dev/null)" ]; then
    echo "ERROR: no vendored tests. Run $HERE/sync.sh first." >&2
    exit 1
fi

machine_guard || exit 1

FILTER=("$@")

cleanup() {
    if [ "$KEEP_MACHINE" = "1" ]; then
        echo "Keeping '$TEST_MACHINE' (KEEP_MACHINE=1); results are in $REMOTE_DIR"
    else
        machine_destroy
    fi
    machine_restore_running
}
trap cleanup EXIT

echo "=== podman system tests ($(cat "$VENDOR/.podman-version" 2>/dev/null || echo 'unknown version')) ==="

machine_stash_running
machine_create || exit 1

# Try a configuration change against the suite without waiting ~50 minutes for a
# rebuild: GUEST_PATCH points at a script that is run inside the fresh machine
# before the tests start.
if [ -n "${GUEST_PATCH:-}" ]; then
    echo "Applying guest patch: $GUEST_PATCH"
    machine_run_script < "$GUEST_PATCH"
fi

guest_podman_version=$(machine_ssh 'podman --version' 2>/dev/null | tr -d '\r')
vendored_version=$(cat "$VENDOR/.podman-version" 2>/dev/null | tr -d 'v')
echo "guest: $guest_podman_version, tests vendored from podman $vendored_version"
case "$guest_podman_version" in
    *"$vendored_version"*) ;;
    *) echo "WARNING: the vendored suite does not match the guest's podman."
       echo "         Set PODMAN_VERSION and re-run sync.sh to realign." ;;
esac

# The suite shells out to these. skopeo in particular is not optional: the
# suite's own setup uses it to cache the test image, and without it every file
# fails in setup_suite before a single test runs.
echo "Installing test dependencies in the machine..."
machine_run_script <<'DEPS' 2>&1 | tail -4
set -u
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
missing=""
for pkg in bats skopeo jq socat ncat nmap gzip xz-utils tar apache2-utils openssl catatonit; do
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done
[ -n "$missing" ] && echo "WARNING: could not install:$missing"
for cmd in bats skopeo jq socat; do
    command -v "$cmd" >/dev/null || echo "MISSING COMMAND: $cmd"
done
echo "dependencies ready"
DEPS

echo "Copying the suite into the machine..."
machine_ssh "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR" >/dev/null
tar -C "$VENDOR" -cf - . | machine_ssh "tar -C $REMOTE_DIR -xf -"

# Build the list of test files to run.
if [ ${#FILTER[@]} -eq 0 ]; then
    run_files="$REMOTE_DIR/*.bats"
else
    run_files=""
    for f in "${FILTER[@]}"; do
        run_files="$run_files $REMOTE_DIR/${f}*.bats"
    done
fi

podman_cmd="podman"
[ "$ROOTFUL" = "1" ] && podman_cmd="sudo podman"

echo "Running..."
echo
machine_ssh "cd $REMOTE_DIR && PODMAN='$podman_cmd' bats --print-output-on-failure $run_files"
rc=$?

echo
if [ $rc -eq 0 ]; then
    echo "podman system tests passed"
else
    echo "podman system tests failed (exit $rc)"
fi
exit $rc
