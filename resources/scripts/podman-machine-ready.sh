#!/bin/bash
set -x

logger "podman-machine-ready: Starting"

# Maximum wait times
MAX_WAIT_IGNITION=60
MAX_WAIT_NETWORK=30
MAX_WAIT_SSH=30

# Wait for Ignition to complete (with timeout)
logger "podman-machine-ready: Waiting for Ignition provider"
WAITED=0
while [ ! -f /var/lib/ignition-provider-complete ]; do
    if [ $WAITED -ge $MAX_WAIT_IGNITION ]; then
        logger "ERROR: Ignition provider timeout after ${WAITED}s"
        exit 1
    fi
    sleep 0.5
    WAITED=$((WAITED + 1))
done
logger "podman-machine-ready: Ignition provider completed"

# Wait for network (with timeout)
logger "podman-machine-ready: Waiting for network"
WAITED=0
while ! ip addr show | grep -q "inet "; do
    if [ $WAITED -ge $MAX_WAIT_NETWORK ]; then
        logger "ERROR: Network failed to start after ${WAITED}s"
        logger "ERROR: Machine cannot function without network"
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
logger "podman-machine-ready: Network ready"

# Wait for SSH (with timeout)
logger "podman-machine-ready: Waiting for SSH"
WAITED=0
while ! systemctl is-active --quiet ssh.service; do
    if [ $WAITED -ge $MAX_WAIT_SSH ]; then
        logger "ERROR: SSH failed to start after ${WAITED}s"
        logger "ERROR: Machine cannot function without SSH"
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
logger "podman-machine-ready: SSH ready"

sleep 2

logger "podman-machine-ready: Sending ready signal to host via vsock port 1025"

# CRITICAL FIX: Connect to host (CID 2) on vsock port 1025 and send "Ready"
# This matches the official Podman machine implementation:
# /bin/sh -c '/usr/bin/echo Ready | socat - VSOCK-CONNECT:2:1025'
# CID 2 = VMADDR_CID_HOST (the host machine)
/usr/bin/echo Ready | socat - VSOCK-CONNECT:2:1025

if [ $? -eq 0 ]; then
    logger "podman-machine-ready: Ready signal sent successfully"
else
    logger "podman-machine-ready: Failed to send ready signal, retrying..."
    sleep 1
    /usr/bin/echo Ready | socat - VSOCK-CONNECT:2:1025
fi

logger "podman-machine-ready: Service completed"
