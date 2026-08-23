#!/bin/bash
#
# Layer 3 - the machine lifecycle, on a throwaway machine created from the image
# under test. DESTRUCTIVE: it creates and deletes machines.
#
# This is the layer that catches an image which builds fine and then does not
# boot, does not finish Ignition, or never signals ready - failures that only
# show up as "podman machine start" hanging forever.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

machine_guard || exit 1

KEEP_MACHINE="${KEEP_MACHINE:-0}"

cleanup() {
    if [ "$KEEP_MACHINE" = "1" ]; then
        echo "Keeping '$TEST_MACHINE' (KEEP_MACHINE=1)"
    else
        machine_destroy
    fi
    machine_restore_running
}
trap cleanup EXIT

test_01_machine_boots() {
    # Everything else depends on this, so it runs first (alphabetical order).
    machine_stash_running
    local start_ts end_ts
    start_ts=$(date +%s)
    if machine_create; then
        end_ts=$(date +%s)
        t_pass "machine created and reachable over ssh"
        t_info "took $((end_ts - start_ts))s from init to ssh"
    else
        t_fail "machine created and reachable over ssh" \
            "see the serial console: $(ls "${TMPDIR:-/tmp}"/podman/"$TEST_MACHINE".log 2>/dev/null || echo 'no console log')"
        t_summary
        exit 1
    fi
}

test_02_ignition_completed() {
    local marker user
    marker=$(machine_ssh 'test -f /var/lib/ignition-provider-complete && echo yes || echo no' 2>/dev/null | tr -d '\r')
    assert_eq "yes" "$marker" "the Ignition provider ran to completion"

    user=$(machine_ssh 'id -un' 2>/dev/null | tr -d '\r')
    assert_eq "core" "$user" "Ignition created the machine user"

    local uid
    uid=$(machine_ssh 'id -u' 2>/dev/null | tr -d '\r')
    assert_matches "$uid" '^[0-9]+$' "the user has the UID Ignition assigned ($uid)"
}

test_03_post_ignition_setup_ran() {
    local sudoers journal policy
    sudoers=$(machine_ssh 'sudo -n true && echo yes || echo no' 2>/dev/null | tr -d '\r')
    assert_eq "yes" "$sudoers" "passwordless sudo is configured"

    journal=$(machine_ssh 'id -nG' 2>/dev/null | tr -d '\r')
    assert_contains "$journal" "systemd-journal" "the user was added to systemd-journal"

    policy=$(machine_ssh 'test -f /etc/containers/policy.json || test -f ~/.config/containers/policy.json && echo yes || echo no' 2>/dev/null | tr -d '\r')
    assert_eq "yes" "$policy" "an image trust policy is in place"
}

test_04_resources_match_the_request() {
    local cpus mem
    cpus=$(machine_ssh 'nproc' 2>/dev/null | tr -d '\r')
    assert_eq "$TEST_MACHINE_CPUS" "$cpus" "the machine has the requested CPU count"

    mem=$(machine_ssh "awk '/MemTotal/ {print int(\$2/1024)}' /proc/meminfo" 2>/dev/null | tr -d '\r')
    if [ -n "$mem" ] && [ "$mem" -ge $((TEST_MACHINE_MEMORY - 512)) ]; then
        t_pass "the machine has roughly the requested memory (${mem}M)"
    else
        t_fail "the machine has roughly the requested memory" "asked ${TEST_MACHINE_MEMORY}M, got ${mem}M"
    fi

    local disk
    disk=$(machine_ssh "df -BG --output=size / | tail -1 | tr -dc '0-9'" 2>/dev/null | tr -d '\r')
    if [ -n "$disk" ] && [ "$disk" -ge $((TEST_MACHINE_DISK - 2)) ]; then
        t_pass "the root filesystem grew to the requested disk size (${disk}G)"
    else
        t_fail "the root filesystem grew to the requested disk size" \
            "asked ${TEST_MACHINE_DISK}G, got ${disk}G - growpart or growfs did not run"
    fi
}

test_05_host_directories_are_mounted() {
    local mounts
    mounts=$(machine_ssh 'findmnt -no TARGET -t virtiofs' 2>/dev/null | tr -d '\r')
    assert_contains "$mounts" "/Users" "the host home is shared into the machine"
}

test_06_ready_signal_and_api() {
    # podman machine start only returns once the guest signals ready over vsock;
    # reaching this point at all means the signal worked. Check the API too.
    local version
    version=$(podman --connection "$TEST_MACHINE" info --format '{{.Version.Version}}' 2>/dev/null)
    assert_matches "$version" '^[0-9]+\.' "the machine answers the podman API from the host ($version)"
}

test_07_stop_and_start_again() {
    if ! podman machine stop "$TEST_MACHINE" >/dev/null 2>&1; then
        t_fail "the machine stops cleanly" "stop returned non-zero - guest may be unresponsive"
        return
    fi
    t_pass "the machine stops cleanly"

    if podman machine start "$TEST_MACHINE" >/dev/null 2>&1 && machine_wait_ssh; then
        t_pass "the machine starts again after a stop"
    else
        t_fail "the machine starts again after a stop" "second boot failed"
        return
    fi

    # Second boot must not re-run Ignition; podman only serves the config once.
    local marker
    marker=$(machine_ssh 'test -f /var/lib/ignition-provider-complete && echo yes || echo no' 2>/dev/null | tr -d '\r')
    assert_eq "yes" "$marker" "the Ignition marker survives a reboot"
}

test_08_no_failed_units() {
    local failed
    failed=$(machine_ssh 'systemctl list-units --state=failed --no-legend --plain' 2>/dev/null | tr -d '\r')
    if [ -z "$failed" ]; then
        t_pass "no systemd unit failed during boot"
    else
        t_fail "no systemd unit failed during boot" "$(printf '%s' "$failed" | head -3)"
    fi
}

test_09_machine_removes_cleanly() {
    if [ "$KEEP_MACHINE" = "1" ]; then
        t_skip "the machine can be removed" "KEEP_MACHINE=1"
        return
    fi
    machine_destroy
    if machine_exists; then
        t_fail "the machine can be removed" "podman machine rm left it behind"
    else
        t_pass "the machine can be removed"
    fi
}

run_tests
