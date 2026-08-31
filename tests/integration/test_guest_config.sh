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

test_kernel_from_backports() {
    # The image installs the backports kernel and purges the stable one, so there
    # is exactly one kernel and it is the newer one.
    local release major
    release=$(guest 'uname -r' 2>/dev/null | tr -d '\r')
    major=${release%%.*}
    if [ "${major:-0}" -ge 7 ]; then
        t_pass "running the backports kernel ($release)"
    else
        t_fail "running the backports kernel" "still on $release - did the backports install fail during the build?"
    fi

    local count
    count=$(guest 'ls /boot/vmlinuz-* 2>/dev/null | wc -l' 2>/dev/null | tr -d '\r ')
    assert_eq "1" "$count" "the image carries exactly one kernel"

    # eBPF CO-RE needs BTF, and SentinelOne's sensors depend on it.
    local btf
    btf=$(guest 'test -r /sys/kernel/btf/vmlinux && echo yes || echo no' 2>/dev/null | tr -d '\r')
    assert_eq "yes" "$btf" "the kernel exposes BTF for eBPF programs"
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

test_machine_identity_is_its_own() {
    # Host keys and machine-id must have been created by this machine, not by the
    # build - otherwise every deployment from the image shares them.
    local built keytime
    built=$(guest 'stat -c %Y /var/log/image-build-install.log 2>/dev/null || echo 0' 2>/dev/null | tr -d '\r')
    keytime=$(guest 'stat -c %Y /etc/ssh/ssh_host_ed25519_key 2>/dev/null || echo 0' 2>/dev/null | tr -d '\r')

    if [ "${keytime:-0}" -eq 0 ]; then
        t_fail "the machine has its own ssh host key" "no host key at all - sshd cannot be running"
    elif [ "${keytime:-0}" -gt "${built:-0}" ]; then
        t_pass "the ssh host key was generated on the machine, not in the image"
    else
        t_fail "the ssh host key was generated on the machine, not in the image" \
            "the key predates the image build, so every deployment shares it"
    fi

    local mid
    mid=$(guest 'cat /etc/machine-id 2>/dev/null' 2>/dev/null | tr -d '\r')
    assert_matches "$mid" '^[0-9a-f]{32}$' "the machine has a machine-id"
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

test_diagnostics_find_nothing_wrong() {
    # The diagnostics script only asks about failures this image has actually
    # shipped, so a clean run is a real statement about the machine - and running
    # the repository's copy means this holds even on a guest built from an older
    # image, which is exactly when it matters most.
    local repo_script report faults
    repo_script="$HERE/../../resources/scripts/machine-diagnostics.sh"
    if [ ! -r "$repo_script" ]; then
        t_fail "the diagnostics script is in the repository" "not at $repo_script"
        return
    fi

    guest 'cat > /tmp/machine-diagnostics.sh && chmod +x /tmp/machine-diagnostics.sh' \
        < "$repo_script" >/dev/null 2>&1
    report=$(guest 'sudo /tmp/machine-diagnostics.sh' 2>&1 | tr -d '\r')
    guest 'rm -f /tmp/machine-diagnostics.sh' >/dev/null 2>&1

    if [ -z "$report" ]; then
        t_fail "the diagnostics run in the guest" "no output at all"
        return
    fi
    t_pass "the diagnostics run in the guest"

    faults=$(printf '%s\n' "$report" | grep -c '^  FAULT')
    if [ "${faults:-0}" -eq 0 ]; then
        t_pass "the diagnostics report no faults"
    else
        t_fail "the diagnostics report no faults" \
            "$(printf '%s\n' "$report" | grep '^  FAULT')"
    fi

    # A checker that can only ever say "ok" proves nothing, so make it prove it
    # still notices: nobody is not in systemd-journal.
    local negative
    guest 'cat > /tmp/machine-diagnostics.sh && chmod +x /tmp/machine-diagnostics.sh' \
        < "$repo_script" >/dev/null 2>&1
    negative=$(guest 'sudo MACHINE_USER=nobody /tmp/machine-diagnostics.sh' 2>&1 | tr -d '\r')
    guest 'rm -f /tmp/machine-diagnostics.sh' >/dev/null 2>&1
    assert_contains "$negative" "FAULT" "the diagnostics still detect a fault when there is one"
}

test_diagnostics_are_installed() {
    local installed
    installed=$(guest 'test -x /usr/local/bin/podman-machine-diagnostics && echo yes || echo no' \
        2>/dev/null | tr -d '\r')
    if [ "$installed" = "yes" ]; then
        t_pass "podman-machine-diagnostics is installed in the guest"
    else
        t_skip "podman-machine-diagnostics is installed in the guest" \
            "this guest predates it - rebuild the image"
    fi
}

run_tests
