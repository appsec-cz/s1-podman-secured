#!/bin/bash
#
# Throwaway podman machine used by the layers that need a running VM.
#
# The destructive layers must never touch the machine someone works on: podman's
# own system tests wipe container storage, and the lifecycle layer deletes the
# machine it tests. Everything here therefore operates on a dedicated machine
# whose name starts with s1-test-, and refuses anything else unless the caller
# insists with ALLOW_UNSAFE_MACHINE=1.

export CONTAINERS_MACHINE_PROVIDER="${CONTAINERS_MACHINE_PROVIDER:-applehv}"

TEST_MACHINE="${TEST_MACHINE:-s1-test}"
TEST_MACHINE_CPUS="${TEST_MACHINE_CPUS:-4}"
TEST_MACHINE_MEMORY="${TEST_MACHINE_MEMORY:-4096}"
TEST_MACHINE_DISK="${TEST_MACHINE_DISK:-30}"
TEST_IMAGE_PATH="${TEST_IMAGE_PATH:-}"

# Name of the machine that is currently running, if any. The non destructive
# layers default to it so they can be pointed at a real machine without ceremony.
machine_current() {
    podman machine list --format json 2>/dev/null \
        | python3 -c 'import json,sys; print(next((m["Name"] for m in json.load(sys.stdin) if m.get("Running")), ""))' 2>/dev/null
}

# Target for the read-only layers: explicit TEST_MACHINE wins, otherwise whatever
# is running right now.
guest_machine() {
    if [ -n "${TEST_MACHINE_EXPLICIT:-}" ]; then
        printf '%s' "$TEST_MACHINE_EXPLICIT"
        return 0
    fi
    local running
    running=$(machine_current)
    if [ -z "$running" ]; then
        echo "ERROR: no podman machine is running - start one or set TEST_MACHINE_EXPLICIT" >&2
        return 1
    fi
    printf '%s' "$running"
}

# Run a command inside the guest_machine.
guest() {
    podman machine ssh "$(guest_machine)" "$@"
}

# Run a script from stdin inside the guest_machine.
guest_script() {
    podman machine ssh "$(guest_machine)" 'bash -s'
}

machine_guard() {
    case "$TEST_MACHINE" in
        s1-test*) return 0 ;;
    esac
    if [ "${ALLOW_UNSAFE_MACHINE:-0}" = "1" ]; then
        echo "WARNING: operating on '$TEST_MACHINE' because ALLOW_UNSAFE_MACHINE=1" >&2
        return 0
    fi
    cat >&2 <<EOF
ERROR: refusing to use machine '$TEST_MACHINE'.

This layer is destructive - it wipes container storage and deletes the machine.
Use a name starting with s1-test (the default), or set ALLOW_UNSAFE_MACHINE=1 if
you really mean to run it against '$TEST_MACHINE'.
EOF
    return 1
}

machine_image() {
    if [ -n "$TEST_IMAGE_PATH" ]; then
        printf '%s' "$TEST_IMAGE_PATH"
        return 0
    fi
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    local img
    img=$(find "$repo_root/output" -maxdepth 1 -name 'podman-debian*.raw.zst' -type f 2>/dev/null | head -1)
    if [ -z "$img" ]; then
        echo "ERROR: no image found in $repo_root/output - run 'make build' or set TEST_IMAGE_PATH" >&2
        return 1
    fi
    printf '%s' "$img"
}

machine_exists() {
    podman machine inspect "$TEST_MACHINE" >/dev/null 2>&1
}

machine_running() {
    [ "$(podman machine inspect "$TEST_MACHINE" --format '{{.State}}' 2>/dev/null)" = "running" ]
}

# Create the machine from the image under test and start it.
machine_create() {
    machine_guard || return 1
    local image
    image=$(machine_image) || return 1

    if machine_exists; then
        echo "Removing leftover machine '$TEST_MACHINE'"
        machine_destroy
    fi

    echo "Creating machine '$TEST_MACHINE' from $(basename "$image")"
    podman machine init "$TEST_MACHINE" \
        --image "$image" \
        --cpus "$TEST_MACHINE_CPUS" \
        --memory "$TEST_MACHINE_MEMORY" \
        --disk-size "$TEST_MACHINE_DISK" >/dev/null || return 1

    # Podman picks the vfkit REST port without checking whether it is free; when
    # it collides every later machine command fails with "unknown machine state".
    machine_fix_endpoint_port

    echo "Starting machine '$TEST_MACHINE'"
    podman machine start "$TEST_MACHINE" >/dev/null || return 1
    machine_wait_ssh
}

machine_fix_endpoint_port() {
    local cfg="$HOME/.config/containers/podman/machine/applehv/$TEST_MACHINE.json"
    [ -f "$cfg" ] || return 0
    local port
    port=$(grep -o 'http://localhost:[0-9]*' "$cfg" | head -1 | grep -o '[0-9]*$')
    [ -n "$port" ] || return 0
    if lsof -nP -iTCP:"$port" >/dev/null 2>&1; then
        local free
        for free in $(seq 56400 56500); do
            if ! lsof -nP -iTCP:"$free" >/dev/null 2>&1; then
                sed -i '' "s/localhost:$port/localhost:$free/" "$cfg"
                echo "vfkit endpoint port $port was taken, moved to $free"
                return 0
            fi
        done
    fi
}

machine_wait_ssh() {
    local i
    for i in $(seq 1 60); do
        if machine_ssh true >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    echo "ERROR: machine '$TEST_MACHINE' did not become reachable over ssh" >&2
    return 1
}

machine_ssh() {
    podman machine ssh "$TEST_MACHINE" "$@"
}

# Run a script from stdin inside the machine.
machine_run_script() {
    podman machine ssh "$TEST_MACHINE" 'bash -s'
}

machine_destroy() {
    machine_guard || return 1
    podman machine stop "$TEST_MACHINE" >/dev/null 2>&1 || true
    # A guest stuck before userspace ignores ACPI, so fall back to vfkit's API.
    local endpoint
    endpoint=$(podman machine inspect "$TEST_MACHINE" --format '{{.AppleHypervisor.Vfkit.Endpoint}}' 2>/dev/null || true)
    if [ -n "$endpoint" ] && pgrep -f "vfkit.*$TEST_MACHINE" >/dev/null 2>&1; then
        curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
            -d '{"state":"HardStop"}' "$endpoint/vm/state" >/dev/null 2>&1 || true
        sleep 2
    fi
    podman machine rm -f "$TEST_MACHINE" >/dev/null 2>&1 || true
}

# Only one machine can run at a time, so remember what was running and put it back.
MACHINE_PREVIOUSLY_RUNNING=""

machine_stash_running() {
    MACHINE_PREVIOUSLY_RUNNING=$(podman machine list --format json 2>/dev/null \
        | python3 -c 'import json,sys; print(next((m["Name"] for m in json.load(sys.stdin) if m.get("Running")), ""))' 2>/dev/null || true)
    if [ -n "$MACHINE_PREVIOUSLY_RUNNING" ] && [ "$MACHINE_PREVIOUSLY_RUNNING" != "$TEST_MACHINE" ]; then
        echo "Stopping '$MACHINE_PREVIOUSLY_RUNNING' for the duration of the test run"
        podman machine stop "$MACHINE_PREVIOUSLY_RUNNING" >/dev/null 2>&1 || true
    fi
}

machine_restore_running() {
    if [ -n "$MACHINE_PREVIOUSLY_RUNNING" ] && [ "$MACHINE_PREVIOUSLY_RUNNING" != "$TEST_MACHINE" ]; then
        echo "Starting '$MACHINE_PREVIOUSLY_RUNNING' again"
        podman machine start "$MACHINE_PREVIOUSLY_RUNNING" >/dev/null 2>&1 || true
        podman system connection default "$MACHINE_PREVIOUSLY_RUNNING" >/dev/null 2>&1 || true
    fi
}
