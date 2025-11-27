#!/bin/bash
#
# Rosetta x86_64 Binary Translation Activation Script
#
# This script is called by rosetta-activation.service at boot time.
# It tries to mount the Rosetta virtiofs share from the host and
# register the Rosetta binfmt handler for x86_64 binary translation.
#
# If Rosetta is not available (mount fails), it exits silently and
# QEMU qemu-user-static remains as the fallback for x86_64 emulation.
#

set -e

ROSETTA_MOUNT="/run/rosetta"
BINFMT_MISC="/proc/sys/fs/binfmt_misc"

logger "rosetta-activate: Starting Rosetta activation"

# Check if binfmt_misc is mounted
if [ ! -d "$BINFMT_MISC" ]; then
    logger "rosetta-activate: binfmt_misc not mounted, skipping"
    exit 0
fi

# Create mount point
mkdir -p "$ROSETTA_MOUNT"

# Try to mount Rosetta virtiofs share
# This will fail if the host didn't expose it (Rosetta disabled in Podman Desktop)
if ! mount -t virtiofs rosetta "$ROSETTA_MOUNT" 2>/dev/null; then
    logger "rosetta-activate: Rosetta virtiofs not available, using QEMU fallback"
    rmdir "$ROSETTA_MOUNT" 2>/dev/null || true
    exit 0
fi

# Verify Rosetta binary exists
if [ ! -x "$ROSETTA_MOUNT/rosetta" ]; then
    logger "rosetta-activate: Rosetta binary not found at $ROSETTA_MOUNT/rosetta"
    umount "$ROSETTA_MOUNT" 2>/dev/null || true
    rmdir "$ROSETTA_MOUNT" 2>/dev/null || true
    exit 0
fi

logger "rosetta-activate: Rosetta virtiofs mounted at $ROSETTA_MOUNT"

# Disable QEMU x86_64 handler if present (to avoid conflicts)
if [ -f "$BINFMT_MISC/qemu-x86_64" ]; then
    logger "rosetta-activate: Disabling QEMU x86_64 handler"
    echo -1 > "$BINFMT_MISC/qemu-x86_64" 2>/dev/null || true
fi

# Check if Rosetta is already registered
if [ -f "$BINFMT_MISC/rosetta" ]; then
    logger "rosetta-activate: Rosetta binfmt handler already registered"
    exit 0
fi

# Register Rosetta binfmt handler for x86_64 ELF binaries
# Magic bytes: ELF header for x86_64 (little-endian, 64-bit, machine type 0x3e)
# Flags: OCF = Open interpreter at startup, Credentials from binary, Fix binary path
logger "rosetta-activate: Registering Rosetta binfmt handler"
echo ':rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/run/rosetta/rosetta:OCF' > "$BINFMT_MISC/register"

if [ -f "$BINFMT_MISC/rosetta" ]; then
    logger "rosetta-activate: Rosetta x86_64 binary translation activated successfully"
    echo "Rosetta x86_64 binary translation activated"
else
    logger "rosetta-activate: Failed to register Rosetta binfmt handler"
    exit 1
fi
