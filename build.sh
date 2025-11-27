#!/bin/bash
#
# Podman Machine Image Builder
#
# Builds custom Debian 13 image for Podman machines with:
# - Offline package installation
# - Ignition provider for Podman Desktop compatibility
# - Optional SentinelOne agent
# - Rosetta x86_64 acceleration support
#
set -euo pipefail

# Configuration
ARCH="${ARCH:-$(uname -m)}"
IMAGE_SIZE="${IMAGE_SIZE:-10G}"
IMAGE_NAME="${IMAGE_NAME:-podman-debian}"
INSTALL_SENTINELONE="${INSTALL_SENTINELONE:-1}"
SENTINELONE_TOKEN="${SENTINELONE_TOKEN:-}"
VERBOSE="${VERBOSE:-0}"
DEBUG_BUILD="${DEBUG_BUILD:-0}"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/cache"
OUTPUT_DIR="$SCRIPT_DIR/output"
RESOURCES_DIR="$SCRIPT_DIR/resources"
DEBS_DIR="$SCRIPT_DIR/debs"

mkdir -p "$CACHE_DIR" "$OUTPUT_DIR"

echo "========================================"
echo "Building: $IMAGE_NAME (Debian 13 $ARCH)"
echo "========================================"
echo ""

# Validate resources directory exists
if [ ! -d "$RESOURCES_DIR" ]; then
    echo "ERROR: resources/ directory not found"
    echo "Expected: $RESOURCES_DIR"
    exit 1
fi

# Validate required files
REQUIRED_FILES=(
    "$RESOURCES_DIR/install.sh"
    "$RESOURCES_DIR/scripts/ignition-provider.py"
    "$RESOURCES_DIR/scripts/post-ignition-setup.sh"
    "$RESOURCES_DIR/scripts/podman-machine-ready.sh"
    "$RESOURCES_DIR/scripts/rosetta-activate.sh"
    "$RESOURCES_DIR/services/ignition-provider.service"
    "$RESOURCES_DIR/services/post-ignition-setup.service"
    "$RESOURCES_DIR/services/podman-machine-ready.service"
    "$RESOURCES_DIR/services/rosetta-activation.service"
    "$RESOURCES_DIR/configs/containers.conf"
    "$RESOURCES_DIR/configs/storage.conf"
    "$RESOURCES_DIR/configs/99-podman.conf"
    "$RESOURCES_DIR/configs/10-vz-nat.network"
    "$RESOURCES_DIR/configs/delegate.conf"
    "$RESOURCES_DIR/configs/podman-machine.conf"
)

echo "Validating resources..."
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file not found: $file"
        exit 1
    fi
done
echo "✓ All resources validated"

# Architecture mapping for Debian
case "$ARCH" in
    aarch64|arm64) DEBIAN_ARCH="arm64" ;;
    x86_64|amd64) DEBIAN_ARCH="amd64" ;;
    *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Debian 13 (trixie) cloud image URL
DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-${DEBIAN_ARCH}.qcow2"
CHECKSUM_URL="https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
BASE_IMAGE="$CACHE_DIR/debian-13-${DEBIAN_ARCH}.qcow2"
CHECKSUM_FILE="$CACHE_DIR/debian-13-${DEBIAN_ARCH}.sha512"

# Download Debian cloud image if not cached
if [ ! -f "$BASE_IMAGE" ]; then
    echo "Downloading Debian cloud image..."
    echo "URL: $DEBIAN_URL"

    if ! curl -L -o "$BASE_IMAGE" \
        --fail --connect-timeout 30 --max-time 600 \
        --retry 3 --retry-delay 5 --progress-bar \
        "$DEBIAN_URL"; then
        echo "ERROR: Failed to download Debian image"
        rm -f "$BASE_IMAGE"
        exit 1
    fi

    echo "Download complete!"

    # Checksum verification
    echo "Downloading checksum..."
    if curl -L -o "$CHECKSUM_FILE" --fail --connect-timeout 30 --max-time 30 "$CHECKSUM_URL"; then
        echo "Verifying checksum..."
        EXPECTED_CHECKSUM=$(grep "debian-13-generic-${DEBIAN_ARCH}.qcow2" "$CHECKSUM_FILE" | awk '{print $1}')
        if [ -n "$EXPECTED_CHECKSUM" ]; then
            ACTUAL_CHECKSUM=$(sha512sum "$BASE_IMAGE" | awk '{print $1}')
            if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
                echo "✓ Checksum verification passed"
            else
                echo "ERROR: Checksum verification FAILED"
                rm -f "$BASE_IMAGE" "$CHECKSUM_FILE"
                exit 1
            fi
        fi
    fi
else
    echo "Using cached image: $BASE_IMAGE"
fi

# Create working copy
WORK_IMAGE="$CACHE_DIR/${IMAGE_NAME}.qcow2"
echo "Creating working copy..."
cp "$BASE_IMAGE" "$WORK_IMAGE"

# Resize image
echo "Resizing image to $IMAGE_SIZE..."
qemu-img resize "$WORK_IMAGE" "$IMAGE_SIZE"

# Download Podman packages (if not cached)
if [ ! -d "$DEBS_DIR" ] || [ -z "$(ls -A $DEBS_DIR 2>/dev/null)" ]; then
    echo ""
    echo "Downloading Podman packages..."
    mkdir -p "$DEBS_DIR"

    TEMP_CONTAINER="$CACHE_DIR/debootstrap-temp"
    rm -rf "$TEMP_CONTAINER"
    mkdir -p "$TEMP_CONTAINER"

    if ! command -v debootstrap &> /dev/null; then
        echo "ERROR: debootstrap not installed"
        exit 1
    fi

    echo "Creating temporary Debian 13 environment..."
    sudo debootstrap --variant=minbase trixie "$TEMP_CONTAINER" http://deb.debian.org/debian

    echo "Setting up chroot environment..."
    sudo mount --bind /dev "$TEMP_CONTAINER/dev"
    sudo mount --bind /proc "$TEMP_CONTAINER/proc"
    sudo mount --bind /sys "$TEMP_CONTAINER/sys"

    echo "Downloading required packages..."
    sudo chroot "$TEMP_CONTAINER" /bin/bash -c "
        apt-get update
        cd /tmp
        apt-get download \
            podman conmon containernetworking-plugins netavark aardvark-dns \
            slirp4netns passt uidmap fuse-overlayfs crun openssh-server socat \
            dbus-user-session systemd-container iptables nftables iproute2 \
            qemu-user qemu-user-binfmt podman-docker cifs-utils nfs-common \
            procps chrony 2>/dev/null || true
    "

    sudo cp "$TEMP_CONTAINER"/tmp/*.deb "$DEBS_DIR/" 2>/dev/null || true
    sudo chown -R $(id -u):$(id -g) "$DEBS_DIR"

    PKG_COUNT=$(ls -1 "$DEBS_DIR"/*.deb 2>/dev/null | wc -l)
    if [ "$PKG_COUNT" -eq 0 ]; then
        echo "ERROR: Package download failed"
        exit 1
    fi
    echo "✓ Downloaded $PKG_COUNT packages"

    sudo umount "$TEMP_CONTAINER/dev" 2>/dev/null || true
    sudo umount "$TEMP_CONTAINER/proc" 2>/dev/null || true
    sudo umount "$TEMP_CONTAINER/sys" 2>/dev/null || true
    sudo rm -rf "$TEMP_CONTAINER"
else
    echo ""
    echo "Using cached packages in $DEBS_DIR/"
    PKG_COUNT=$(ls -1 "$DEBS_DIR"/*.deb 2>/dev/null | wc -l)
    echo "✓ Using $PKG_COUNT cached packages"
fi

# Customize image
echo ""
echo "Customizing image..."

VIRT_CUSTOMIZE_ARGS=(
    --add "$WORK_IMAGE"
    --hostname podman-machine
    --copy-in "$DEBS_DIR:/tmp/"
    --copy-in "$RESOURCES_DIR:/tmp/"
)

[ "$VERBOSE" = "1" ] && VIRT_CUSTOMIZE_ARGS+=(--verbose)

if [ "$DEBUG_BUILD" = "1" ]; then
    echo "DEBUG BUILD enabled"
    touch "$CACHE_DIR/debug-build-marker"
    VIRT_CUSTOMIZE_ARGS+=(--upload "$CACHE_DIR/debug-build-marker:/tmp/debug-build-marker")
fi

# Add SentinelOne if available
if [ "$INSTALL_SENTINELONE" = "1" ]; then
    S1_DEB=$(find "$SCRIPT_DIR" -maxdepth 1 -name "SentinelAgent*.deb" 2>/dev/null | head -n1)
    if [ -n "$S1_DEB" ] && [ -f "$S1_DEB" ]; then
        echo "Found SentinelOne package: $S1_DEB"
        VIRT_CUSTOMIZE_ARGS+=(--upload "$S1_DEB:/tmp/s1.deb")
        if [ -n "$SENTINELONE_TOKEN" ]; then
            echo "SentinelOne registration token provided"
            echo -n "$SENTINELONE_TOKEN" > "$CACHE_DIR/sentinelone-token"
            VIRT_CUSTOMIZE_ARGS+=(--upload "$CACHE_DIR/sentinelone-token:/tmp/sentinelone-token")
        fi
    else
        echo "No SentinelOne package found in project root"
    fi
fi

# Run install script
VIRT_CUSTOMIZE_ARGS+=(
    --run-command "set -o pipefail && bash -x /tmp/resources/install.sh 2>&1 | tee /var/log/image-build-install.log"
    --run-command "rm -rf /tmp/resources /tmp/debs"
)

virt-customize "${VIRT_CUSTOMIZE_ARGS[@]}"

# Extract install log if verbose
if [ "$VERBOSE" = "1" ]; then
    echo ""
    echo "=== Install Script Output ==="
    virt-cat -a "$WORK_IMAGE" /var/log/image-build-install.log 2>/dev/null || echo "WARNING: Could not extract install log"
fi

# Create output
echo ""
echo "Creating RAW image..."
OUTPUT_RAW="$OUTPUT_DIR/${IMAGE_NAME}.raw"
qemu-img convert -f qcow2 -O raw "$WORK_IMAGE" "$OUTPUT_RAW"

echo "Compressing..."
zstd -f "$OUTPUT_RAW"
sha256sum "$OUTPUT_RAW.zst" > "$OUTPUT_RAW.zst.sha256"
rm -f "$OUTPUT_RAW"

echo ""
echo "========================================"
echo "=== Build complete ==="
echo "========================================"
echo "Image: $OUTPUT_RAW.zst"
echo "Checksum: $OUTPUT_RAW.zst.sha256"
echo ""
echo "Usage:"
echo "  podman machine init test --image $OUTPUT_RAW.zst"
echo ""
