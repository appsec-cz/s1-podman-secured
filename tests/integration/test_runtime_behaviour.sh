#!/bin/bash
#
# Layer 4b - what the machine has to be able to do.
#
# Storage, logs, networking and Docker compatibility, each pinned to a failure
# that shipped: containers stored outside btrfs subvolumes, podman logs silently
# empty, published ports unreachable from macOS, docker.sock pointing nowhere.
#
# Creates and removes its own containers, so it is safe against a machine in use.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

MACHINE=$(guest_machine) || exit 1
TEST_IMG="${TEST_CONTAINER_IMAGE:-docker.io/library/alpine:latest}"
PREFIX="s1test$$"

printf 'Testing guest: %s\n' "$MACHINE"

cleanup() {
    guest "podman rm -f -i \$(podman ps -aq --filter name=$PREFIX) >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test_container_runs() {
    local out
    out=$(guest "podman run --rm --name ${PREFIX}run $TEST_IMG echo CONTAINER_OK" 2>&1 | tr -d '\r')
    assert_contains "$out" "CONTAINER_OK" "a container runs and its output comes back"
}

test_image_layers_are_btrfs_subvolumes() {
    # The point of the whole btrfs exercise: layers are subvolumes, not overlay dirs.
    guest "podman pull -q $TEST_IMG >/dev/null 2>&1" >/dev/null 2>&1
    local subvols graphroot
    graphroot=$(guest 'podman info --format "{{.Store.GraphRoot}}"' 2>/dev/null | tr -d '\r')
    subvols=$(guest 'sudo btrfs subvolume list /' 2>/dev/null)
    assert_contains "$subvols" "btrfs/subvolumes" "image layers are stored as btrfs subvolumes"
    assert_contains "$subvols" "$(printf '%s' "$graphroot" | sed 's|^/||')" \
        "the subvolumes live under the graph root ($graphroot)"
}

test_logs_are_readable() {
    # Regression: with journald as the driver and no journal access, podman logs
    # returned nothing, and everything that waits for a log line hung - this is
    # exactly how kind failed.
    local out
    guest "podman run -d --name ${PREFIX}log $TEST_IMG sh -c 'echo LOG_MARKER_XYZ; sleep 5'" >/dev/null 2>&1
    sleep 4
    out=$(guest "podman logs ${PREFIX}log" 2>&1 | tr -d '\r')
    assert_contains "$out" "LOG_MARKER_XYZ" "podman logs returns container output"

    local driver
    driver=$(guest 'podman info --format "{{.Host.LogDriver}}"' 2>/dev/null | tr -d '\r')
    t_info "log driver: $driver"
    guest "podman rm -f ${PREFIX}log" >/dev/null 2>&1
}

test_published_port_reaches_the_host() {
    # Regression: podman only asks gvproxy to forward ports when it recognises it
    # runs inside a machine. When the marker was hidden, every published port was
    # unreachable from macOS - kubectl could not talk to a kind cluster, and
    # 'podman run -p' was broken in general.
    local port=18234
    guest "podman run -d --name ${PREFIX}net -p 0.0.0.0:$port:80 docker.io/library/nginx:alpine" >/dev/null 2>&1
    local i inside=""
    for i in $(seq 1 10); do
        inside=$(guest "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:$port/" 2>/dev/null | tr -d '\r')
        [ "$inside" = "200" ] && break
        sleep 2
    done
    assert_eq "200" "$inside" "the container serves inside the VM"

    local outside
    outside=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$port/" 2>/dev/null)
    assert_eq "200" "$outside" "the published port is reachable from macOS"

    if [ "$outside" != "200" ]; then
        t_info "gvproxy forwards: $(guest 'curl -s --max-time 5 http://192.168.127.1/services/forwarder/all' 2>/dev/null | head -c 200)"
    fi
    guest "podman rm -f ${PREFIX}net" >/dev/null 2>&1
}

test_container_dns() {
    # netavark plus aardvark-dns: containers on a network resolve each other by name.
    local net="${PREFIX}dns"
    guest "podman network create $net" >/dev/null 2>&1
    guest "podman run -d --name ${PREFIX}dnssrv --network $net docker.io/library/nginx:alpine" >/dev/null 2>&1
    sleep 3
    # getent exits non-zero when the name does not resolve, and avoids the
    # quoting layers that nesting a shell inside podman inside ssh would add.
    local out
    out=$(guest_script <<EOS 2>&1 | tr -d '\r'
podman run --rm --network $net $TEST_IMG getent hosts ${PREFIX}dnssrv || echo NO_RESOLVE
EOS
)
    assert_not_contains "$out" "NO_RESOLVE" "containers resolve each other by name"
    assert_matches "$out" '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "the resolved name has an address"
    t_info "$(printf '%s' "$out" | head -1)"
    guest "podman rm -f ${PREFIX}dnssrv >/dev/null 2>&1; podman network rm -f $net" >/dev/null 2>&1
}

test_docker_compatibility_in_guest() {
    local out
    out=$(guest 'ls -la /run/docker.sock /var/run/docker.sock 2>&1' 2>/dev/null)
    assert_contains "$out" "podman.sock" "docker.sock points at podman's API socket"

    out=$(guest 'curl -s --unix-socket /run/docker.sock http://d/version' 2>/dev/null)
    assert_contains "$out" "Podman Engine" "the Docker API socket answers"
    local api
    api=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ApiVersion",""))' 2>/dev/null)
    assert_matches "$api" '^1\.[0-9]+$' "the Docker API reports a version ($api)"

    out=$(guest 'command -v docker docker-compose 2>/dev/null' 2>/dev/null)
    assert_contains "$out" "docker" "a docker CLI shim exists in the guest"
}

test_docker_compatibility_on_host() {
    # The host half of Docker compatibility is podman-mac-helper; without it any
    # client that hardcodes /var/run/docker.sock talks to nothing.
    if [ ! -S /var/run/docker.sock ]; then
        t_fail "/var/run/docker.sock exists on the host" "run: sudo podman-mac-helper install"
        return
    fi
    local out
    out=$(curl -s --max-time 5 --unix-socket /var/run/docker.sock http://d/version 2>/dev/null)
    if printf '%s' "$out" | grep -q "Podman Engine"; then
        t_pass "the host docker socket reaches podman"
    else
        t_fail "the host docker socket reaches podman" \
            "/var/run/docker.sock does not answer as podman - is podman-mac-helper installed?"
    fi
}

test_short_image_names_resolve() {
    # Docker resolves 'alpine' to docker.io; podman needs unqualified-search-registries.
    local out
    out=$(guest "podman run --rm alpine:latest echo SHORTNAME_OK" 2>&1 | tr -d '\r')
    assert_contains "$out" "SHORTNAME_OK" "unqualified image names resolve"
}

test_init_process_support() {
    # podman-docker parity: --init needs catatonit present in the image.
    local out
    out=$(guest "podman run --rm --init $TEST_IMG echo INIT_OK" 2>&1 | tr -d '\r')
    assert_contains "$out" "INIT_OK" "containers can run with --init"
}

test_x86_64_translation() {
    # Rosetta translates natively on Apple Silicon and qemu-user emulates when it
    # is absent. Either way an amd64 container has to run; which one did the work
    # is worth reporting, because the difference is large.
    local out
    out=$(guest "podman run --rm --arch amd64 $TEST_IMG uname -m" 2>&1 | tr -d '\r')
    assert_contains "$out" "x86_64" "an amd64 container runs on this machine"

    local handlers
    handlers=$(guest 'ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -E "^(rosetta|qemu-x86_64)$" | tr "\n" " "' 2>/dev/null | tr -d '\r')
    if printf '%s' "$handlers" | grep -q rosetta; then
        t_pass "Rosetta is handling x86_64 binaries"
        local qemu_state
        qemu_state=$(guest 'cat /proc/sys/fs/binfmt_misc/qemu-x86_64 2>/dev/null | head -1' 2>/dev/null | tr -d '\r')
        t_info "qemu-x86_64 handler: ${qemu_state:-not registered} (fallback)"
    else
        t_skip "Rosetta is handling x86_64 binaries" \
            "only qemu-user is registered - Rosetta is off for this machine, or the host is not Apple Silicon"
        assert_contains "$handlers" "qemu-x86_64" "qemu-user is registered as the fallback"
    fi
}

test_rootful_containers() {
    local out
    out=$(guest "sudo podman run --rm $TEST_IMG echo ROOTFUL_OK" 2>&1 | tr -d '\r')
    assert_contains "$out" "ROOTFUL_OK" "rootful podman runs containers"
}

run_tests
