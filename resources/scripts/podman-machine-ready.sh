#!/bin/bash
#
# Tells the host the machine is up, then records what state it came up in.
#
# "podman machine start" blocks on the vsock signal below, so everything before
# it is on the critical path and stays cheap. The diagnostics run afterwards.
set -x

# Waits are in seconds; each loop sleeps a whole one so the timeout it reports
# is the time that actually passed.
MAX_WAIT_IGNITION=30
MAX_WAIT_NETWORK=30
MAX_WAIT_SSH=30

BOOT_START=$SECONDS

logger "podman-machine-ready: Starting"

# Wait for a condition, logging how long it took - a slow phase is the first
# clue when a machine takes minutes to come up instead of seconds.
wait_for() {
    local what="$1" limit="$2" fatal="$3"; shift 3
    local waited=0 start=$SECONDS
    logger "podman-machine-ready: waiting for $what"
    while ! "$@"; do
        if [ "$waited" -ge "$limit" ]; then
            logger "ERROR: $what did not arrive after ${waited}s"
            [ "$fatal" = "fatal" ] && {
                logger "ERROR: the machine cannot function without $what"
                exit 1
            }
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    logger "podman-machine-ready: $what ready after $((SECONDS - start))s"
    return 0
}

ignition_done() { [ -f /var/lib/ignition-provider-complete ]; }
network_up()    { ip addr show | grep -q "inet "; }
ssh_up()        { systemctl is-active --quiet ssh.service; }

wait_for "the Ignition provider" "$MAX_WAIT_IGNITION" fatal ignition_done
wait_for "the network"           "$MAX_WAIT_NETWORK"  fatal network_up
wait_for "SSH"                   "$MAX_WAIT_SSH"      fatal ssh_up

sleep 2

# CID 2 = VMADDR_CID_HOST. This matches podman's own implementation:
#   /bin/sh -c '/usr/bin/echo Ready | socat - VSOCK-CONNECT:2:1025'
#
# A machine that boots cleanly and never signals looks to the user like a hang
# with nothing to go on, so every attempt is recorded and the outcome is left
# where the diagnostics can find it.
send_ready() {
    local attempt rc
    for attempt in 1 2 3; do
        /usr/bin/echo Ready | socat - VSOCK-CONNECT:2:1025
        rc=$?
        if [ "$rc" -eq 0 ]; then
            logger "podman-machine-ready: ready signal sent on attempt $attempt"
            echo "sent on attempt $attempt after $((SECONDS - BOOT_START))s" \
                > /run/podman-machine-ready-signal
            return 0
        fi
        logger "ERROR: ready signal attempt $attempt failed (socat exit $rc)"
        sleep 1
    done
    logger "ERROR: the host was never told this machine is ready"
    echo "failed after 3 attempts (socat exit $rc)" > /run/podman-machine-ready-signal
    return 1
}

send_ready

# Past the critical path: the host is no longer waiting on us.
if [ -x /usr/local/bin/podman-machine-diagnostics ]; then
    /usr/local/bin/podman-machine-diagnostics > /var/log/podman-machine-diagnostics.log 2>&1
    logger -t podman-machine-diagnostics -f /var/log/podman-machine-diagnostics.log
    faults=$(grep -c '^  FAULT' /var/log/podman-machine-diagnostics.log 2>/dev/null)
    if [ "${faults:-0}" -gt 0 ]; then
        logger "podman-machine-ready: $faults fault(s) found - see /var/log/podman-machine-diagnostics.log"
    fi
fi

# First beat on the serial console, so the host has a verdict about this machine
# even if ssh never becomes usable. The timer takes over from here.
if [ -x /usr/local/bin/podman-machine-health ]; then
    /usr/local/bin/podman-machine-health || true
fi

logger "podman-machine-ready: boot complete in $((SECONDS - BOOT_START))s"
