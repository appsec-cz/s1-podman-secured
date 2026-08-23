#!/bin/bash
#
# Layer 4a - the image's configuration is actually in effect in the running guest.
#
# Writing a config file into the image is not the same as podman using it. Every
# assertion here failed at some point while the file itself was perfectly fine.
# Non destructive: reads state, creates nothing.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

MACHINE=$(guest_machine) || exit 1
printf 'Testing guest: %s\n' "$MACHINE"

test_root_filesystem() {
    local mnt
    mnt=$(guest 'findmnt -no FSTYPE,OPTIONS /' 2>/dev/null)
    assert_contains "$mnt" "btrfs" "root filesystem is btrfs"
    assert_contains "$mnt" "compress=zstd" "root filesystem is compressed"
    assert_contains "$mnt" "noatime" "root filesystem is mounted noatime"

    local subvols
    subvols=$(guest 'sudo btrfs subvolume list /' 2>/dev/null)
    assert_not_contains "$subvols" "ext2_saved" "the ext4 rollback subvolume was dropped"
}

test_disk_was_grown() {
    # x-systemd.growfs plus cloud-init's growpart should claim the whole disk;
    # if they do not, the machine silently ignores --disk-size.
    local size_gb disk_gb
    size_gb=$(guest "df -BG --output=size / | tail -1 | tr -dc '0-9'" 2>/dev/null)
    disk_gb=$(podman machine inspect "$MACHINE" --format '{{.Resources.DiskSize}}' 2>/dev/null)
    if [ -z "$size_gb" ] || [ -z "$disk_gb" ]; then
        t_skip "root filesystem fills the disk" "could not read sizes"
        return
    fi
    # allow for filesystem overhead and the ESP
    if [ "$size_gb" -ge $((disk_gb - 2)) ]; then
        t_pass "root filesystem fills the disk (${size_gb}G of ${disk_gb}G)"
    else
        t_fail "root filesystem fills the disk" "only ${size_gb}G of ${disk_gb}G - growpart/growfs did not run"
    fi
}

test_storage_driver() {
    # Regression: podman fell back to overlay because podman 6 mounted the host's
    # config over /etc/containers and hid storage.conf.
    local rootless rootful
    rootless=$(guest 'podman info --format "{{.Store.GraphDriverName}}"' 2>/dev/null | tr -d '\r')
    rootful=$(guest 'sudo podman info --format "{{.Store.GraphDriverName}}"' 2>/dev/null | tr -d '\r')
    assert_eq "btrfs" "$rootless" "rootless podman uses the btrfs driver"
    assert_eq "btrfs" "$rootful" "rootful podman uses the btrfs driver"
}

test_oci_runtime() {
    # Regression: crun was missing from the image and podman quietly used runc.
    local runtime
    runtime=$(guest 'podman info --format "{{.Host.OCIRuntime.Name}}"' 2>/dev/null | tr -d '\r')
    assert_eq "crun" "$runtime" "containers.conf runtime selection is in effect"
}

test_machine_marker_is_visible() {
    # Regression: the marker was hidden, so podman stopped recognising the machine
    # and never forwarded published ports to the host.
    local marker
    marker=$(guest 'cat /etc/containers/podman-machine 2>/dev/null || echo MISSING' 2>/dev/null | tr -d '\r')
    assert_ne "MISSING" "$marker" "podman machine marker is readable at /etc/containers/podman-machine"
}

test_image_configuration_files() {
    local out
    out=$(guest 'for f in /etc/containers/storage.conf /etc/containers/containers.conf \
        /etc/containers/policy.json /usr/share/containers/storage.conf \
        /usr/share/containers/containers.conf; do
            [ -f "$f" ] && echo "present $f" || echo "missing $f"
        done' 2>/dev/null)
    local f
    for f in /etc/containers/storage.conf /etc/containers/containers.conf /etc/containers/policy.json; do
        assert_contains "$out" "present $f" "$f is visible to podman"
    done
}

test_expected_packages() {
    # Regression: apt-get install -f removed packages the build thought it had.
    local out pkg
    for pkg in podman crun btrfs-progs netavark aardvark-dns passt uidmap chrony podman-docker; do
        out=$(guest "dpkg-query -W -f='\${Status}' $pkg 2>/dev/null" 2>/dev/null | tr -d '\r')
        assert_eq "install ok installed" "$out" "$pkg is installed"
    done
}

test_no_docker_engine() {
    local status
    status=$(guest "dpkg-query -W -f='\${Status}' docker.io 2>/dev/null || echo absent" 2>/dev/null | tr -d '\r')
    assert_not_contains "$status" "install ok installed" "no Docker Engine in the image"
}

test_user_can_read_journal() {
    # Regression: without this, podman logs returns nothing and kind never starts.
    local groups
    groups=$(guest 'id -nG' 2>/dev/null | tr -d '\r')
    assert_contains "$groups" "systemd-journal" "the machine user can read the journal"
}

test_services_are_healthy() {
    local svc state
    for svc in ssh.service podman.socket; do
        state=$(guest "systemctl is-active $svc" 2>/dev/null | tr -d '\r')
        assert_eq "active" "$state" "$svc is active"
    done
    local failed
    failed=$(guest 'systemctl list-units --state=failed --no-legend --plain | wc -l' 2>/dev/null | tr -d '\r ')
    if [ "${failed:-0}" -eq 0 ]; then
        t_pass "no failed systemd units"
    else
        t_fail "no failed systemd units" "$(guest 'systemctl list-units --state=failed --no-legend --plain' 2>/dev/null | head -5)"
    fi
}

test_rootless_prerequisites() {
    local subuid delegated
    subuid=$(guest 'grep -c "^core:" /etc/subuid' 2>/dev/null | tr -d '\r ')
    assert_eq "1" "$subuid" "subuid range is configured for the machine user"

    delegated=$(guest 'cat /sys/fs/cgroup/user.slice/user-$(id -u)/user@$(id -u).service/cgroup.controllers 2>/dev/null || cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers' 2>/dev/null)
    for c in cpu memory pids; do
        assert_contains "$delegated" "$c" "cgroup controller '$c' is delegated to the user"
    done
}

run_tests
