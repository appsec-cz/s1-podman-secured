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
# The agent is licensed per endpoint and is not redistributable, so it stays out
# of any image that leaves this machine. Images are built without it and the
# agent is installed at deployment time from a copy the operator already holds
# (see docs/deployment-jamf.md). Set INSTALL_SENTINELONE=1 only for an image that
# will not be distributed.
INSTALL_SENTINELONE="${INSTALL_SENTINELONE:-0}"
SENTINELONE_TOKEN="${SENTINELONE_TOKEN:-}"
VERBOSE="${VERBOSE:-0}"
DEBUG_BUILD="${DEBUG_BUILD:-0}"

# Packages installed into the image.
# Single source of truth: the same list is written into the image as
# /tmp/debs/package-list.txt so install.sh can repair and verify against it.
# Pure podman - no Docker Engine. docker.io also conflicts with podman-docker,
# which is why podman-docker never installed while docker.io was on this list.
#
# ansible-core rather than ansible: it is what provides ansible-playbook, which
# is all "podman machine init --playbook" runs, and it costs 37 packages instead
# of several hundred. Baked in rather than installed on demand at first boot, so
# a playbook still works on a machine with no route to a Debian mirror.
PACKAGES="podman conmon containernetworking-plugins netavark aardvark-dns \
slirp4netns passt uidmap crun openssh-server socat \
dbus-user-session systemd-container iptables nftables iproute2 \
qemu-user qemu-user-binfmt podman-docker cifs-utils nfs-common \
procps chrony btrfs-progs ansible-core"

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
    "$RESOURCES_DIR/configs/ssh-hostkeys.conf"
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

# Convert root filesystem to btrfs
echo ""
echo "Converting root filesystem to btrfs..."

# Find root partition (ext4)
ROOT_PART=$(guestfish --ro -a "$WORK_IMAGE" <<EOF
run
list-filesystems
EOF
)
echo "Detected filesystems: $ROOT_PART"

# Extract the ext4 partition device (e.g., /dev/sda1)
ROOT_DEV=$(echo "$ROOT_PART" | grep -E 'ext[234]' | head -1 | cut -d: -f1)
if [ -z "$ROOT_DEV" ]; then
    echo "ERROR: Could not find ext4 root partition"
    exit 1
fi
echo "Root partition: $ROOT_DEV"

# Grow the partition to use all available space first
echo "Growing partition to use full disk..."
# virt-resize requires output file to exist, create it first
rm -f "$WORK_IMAGE.tmp"
qemu-img create -f qcow2 -o preallocation=off "$WORK_IMAGE.tmp" "$IMAGE_SIZE"
if ! virt-resize --expand "$ROOT_DEV" "$WORK_IMAGE" "$WORK_IMAGE.tmp"; then
    rm -f "$WORK_IMAGE.tmp"
    echo "ERROR: virt-resize failed"
    exit 1
fi
mv "$WORK_IMAGE.tmp" "$WORK_IMAGE"

# Re-detect root partition after resize (partition numbers may change)
echo "Re-detecting root partition after resize..."
ROOT_PART_NEW=$(guestfish --ro -a "$WORK_IMAGE" <<EOF
run
list-filesystems
EOF
)
echo "Filesystems after resize: $ROOT_PART_NEW"
ROOT_DEV=$(echo "$ROOT_PART_NEW" | grep -E 'ext[234]' | head -1 | cut -d: -f1)
if [ -z "$ROOT_DEV" ]; then
    echo "ERROR: Could not find ext4 root partition after resize"
    exit 1
fi
echo "Root partition after resize: $ROOT_DEV"

# Convert ext4 to btrfs using download/convert/upload approach
# guestfish 'sh' command requires mounted FS, but btrfs-convert needs unmounted
echo "Running btrfs-convert..."
PARTITION_IMG="$CACHE_DIR/partition.img"

# Get the OLD UUID from ext4 filesystem BEFORE conversion
echo "  Getting original ext4 UUID..."
OLD_UUID=$(guestfish --ro -a "$WORK_IMAGE" <<EOF
run
vfs-uuid $ROOT_DEV
EOF
)
OLD_UUID=$(echo "$OLD_UUID" | tr -d '[:space:]')
echo "  Original ext4 UUID: $OLD_UUID"

# Download the partition as raw image
echo "  Downloading partition..."
guestfish -a "$WORK_IMAGE" <<EOF
run
download $ROOT_DEV $PARTITION_IMG
EOF

# Convert ext4 to btrfs on the raw partition image
echo "  Converting to btrfs..."
btrfs-convert -p "$PARTITION_IMG"

# Upload the converted partition back
echo "  Uploading converted partition..."
guestfish -a "$WORK_IMAGE" <<EOF
run
upload $PARTITION_IMG $ROOT_DEV
EOF

# Clean up partition image
rm -f "$PARTITION_IMG"

# Get new btrfs UUID and update boot config
echo "Updating boot configuration for btrfs..."

# Get the new UUID from the converted btrfs filesystem
NEW_UUID=$(guestfish --ro -a "$WORK_IMAGE" <<EOF
run
vfs-uuid $ROOT_DEV
EOF
)
NEW_UUID=$(echo "$NEW_UUID" | tr -d '[:space:]')
echo "New btrfs UUID: $NEW_UUID"
echo "Old ext4 UUID: $OLD_UUID"

if [ -z "$OLD_UUID" ] || [ -z "$NEW_UUID" ]; then
    echo "ERROR: Failed to get UUIDs (old=$OLD_UUID, new=$NEW_UUID)"
    exit 1
fi

# virt-resize renumbers partitions: on the Debian cloud image the root partition
# moves from gpt1 to gpt2 and the ESP becomes gpt1, so GRUB's partition hints
# have to follow.
ROOT_PARTNUM="${ROOT_DEV##*[a-z]}"
echo "Root partition number: $ROOT_PARTNUM"

# The EFI stub loader config is rewritten from scratch - it is a three line file
# and this is exactly what grub-install generates. Everything else is patched
# with guestfish 'command'; do NOT use 'sh "if [ -f ... ]; then ...; fi"' here,
# it silently does nothing and the result is an image whose GRUB drops into the
# rescue prompt because it still searches for the old ext4 UUID.
ESP_GRUB_CFG="$CACHE_DIR/esp-grub.cfg"
cat > "$ESP_GRUB_CFG" <<ESPEOF
search.fs_uuid $NEW_UUID root 
set prefix=(\$root)'/boot/grub'
configfile \$prefix/grub.cfg
ESPEOF

guestfish -a "$WORK_IMAGE" -i <<EOF
# Update fstab - filesystem type, mount options and UUID
command "sed -i 's/ext4/btrfs/g' /etc/fstab"
command "sed -i 's/errors=remount-ro/compress=zstd,noatime/g' /etc/fstab"
command "sed -i 's/$OLD_UUID/$NEW_UUID/g' /etc/fstab"

# Update GRUB - filesystem UUID, btrfs module, partition hints
command "sed -i 's/$OLD_UUID/$NEW_UUID/g' /boot/grub/grub.cfg"
command "sed -i 's/insmod ext2/insmod btrfs/g' /boot/grub/grub.cfg"
command "sed -i 's/hd0,gpt1/hd0,gpt$ROOT_PARTNUM/g' /boot/grub/grub.cfg"
command "sed -i 's/ahci0,gpt1/ahci0,gpt$ROOT_PARTNUM/g' /boot/grub/grub.cfg"
command "sed -i 's/$OLD_UUID/$NEW_UUID/g' /etc/default/grub"

# Replace the EFI stub loader config on the ESP
upload $ESP_GRUB_CFG /boot/efi/EFI/debian/grub.cfg
EOF
rm -f "$ESP_GRUB_CFG"

# Verify the bootloader actually points at the converted filesystem - a silent
# no-op here produces an image that never boots, with no error at build time.
#
# This runs twice: once now, and again after virt-customize, because installing a
# kernel triggers update-grub, which regenerates /boot/grub/grub.cfg from scratch.
# Verifying only before the package installation would leave exactly the failure
# this check exists to catch.
verify_boot_config() {
    local when="$1"
    echo "Verifying boot configuration ($when)..."
    local cfg CFG_CONTENT
    for cfg in /boot/efi/EFI/debian/grub.cfg /boot/grub/grub.cfg /etc/fstab; do
        CFG_CONTENT=$(virt-cat -a "$WORK_IMAGE" "$cfg" 2>/dev/null || true)
        if [ -z "$CFG_CONTENT" ]; then
            echo "ERROR: $cfg is missing or unreadable in the image"
            exit 1
        fi
        if echo "$CFG_CONTENT" | grep -q "$OLD_UUID"; then
            echo "ERROR: $cfg still references the old ext4 UUID $OLD_UUID"
            exit 1
        fi
        case "$cfg" in
            *grub.cfg)
                if ! echo "$CFG_CONTENT" | grep -q "$NEW_UUID"; then
                    echo "ERROR: $cfg does not reference the btrfs UUID $NEW_UUID"
                    exit 1
                fi
                ;;
        esac
    done
    echo "Boot configuration updated and verified ($when)"
}

verify_boot_config "after conversion"

echo "Verifying btrfs conversion..."
CONVERTED_FS=$(guestfish --ro -a "$WORK_IMAGE" <<EOF
run
list-filesystems
EOF
)
echo "Filesystems after conversion: $CONVERTED_FS"

if ! echo "$CONVERTED_FS" | grep -q "btrfs"; then
    echo "ERROR: btrfs conversion failed"
    exit 1
fi
echo "Btrfs conversion successful"

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
        apt-get download $PACKAGES 2>/dev/null || true
    "

    sudo cp "$TEMP_CONTAINER"/tmp/*.deb "$DEBS_DIR/" 2>/dev/null || true
    sudo chown -R $(id -u):$(id -g) "$DEBS_DIR"
    printf '%s\n' $PACKAGES > "$DEBS_DIR/package-list.txt"

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
    printf '%s\n' $PACKAGES > "$DEBS_DIR/package-list.txt"
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
        # The agent is the reason this image exists. Silently building without it
        # produces an image that looks fine and is missing its whole point - set
        # INSTALL_SENTINELONE=0 to say you meant it.
        echo "ERROR: INSTALL_SENTINELONE=1 but no SentinelAgent*.deb in $SCRIPT_DIR"
        echo "       Put the agent package there, or build with INSTALL_SENTINELONE=0"
        exit 1
    fi
fi

# Run install script
VIRT_CUSTOMIZE_ARGS+=(
    --run-command "set -o pipefail && bash -x /tmp/resources/install.sh 2>&1 | tee /var/log/image-build-install.log"
    --run-command "rm -rf /tmp/resources /tmp/debs"
)

virt-customize "${VIRT_CUSTOMIZE_ARGS[@]}"

# install.sh replaces the kernel, which regenerates grub.cfg. Check it again.
verify_boot_config "after customization"

INSTALLED_KERNEL=$(virt-ls -a "$WORK_IMAGE" /boot 2>/dev/null | grep '^vmlinuz-' | sed 's/^vmlinuz-//' | sort -V | tr '\n' ' ')
echo "Kernels in the image: ${INSTALLED_KERNEL:-none}"
if [ -z "$INSTALLED_KERNEL" ]; then
    echo "ERROR: no kernel in the image"
    exit 1
fi
if [ "$(printf '%s' "$INSTALLED_KERNEL" | wc -w)" -gt 1 ]; then
    echo "WARNING: more than one kernel is installed, the image is larger than it needs to be"
fi

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
