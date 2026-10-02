#!/bin/bash
#
# Podman Machine Image Builder
#
# Builds custom Debian 13 image for Podman machines with:
# - Packages installed from the Debian archive, security updates included
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
# Single source of truth: the same list is uploaded into the image as
# /tmp/package-list.txt so install.sh can install and verify against it.
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
    "$RESOURCES_DIR/configs/storage-user.conf"
    "$RESOURCES_DIR/configs/99-podman.conf"
    "$RESOURCES_DIR/configs/10-vz-nat.network"
    "$RESOURCES_DIR/configs/delegate.conf"
    "$RESOURCES_DIR/configs/podman-machine.conf"
    "$RESOURCES_DIR/configs/ssh-hostkeys.conf"
    "$RESOURCES_DIR/configs/ssh-after-user-sessions.conf"
    "$RESOURCES_DIR/configs/chrony-podman-machine.conf"
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

# The base image is everything the machine runs on, so it is never used without
# matching Debian's published checksum - not when SHA512SUMS cannot be fetched,
# not when it has no line for this image, and not when it comes from the cache.
# The checksum is kept next to the cached image for exactly that: "latest" moves,
# so a cached image can only be checked against the list it was downloaded with.
IMAGE_FILE_NAME="debian-13-generic-${DEBIAN_ARCH}.qcow2"

expected_checksum() {
    awk -v f="$IMAGE_FILE_NAME" '$2 == f || $2 == "*" f {print $1; exit}' "$CHECKSUM_FILE" 2>/dev/null
}

verify_base_image() {
    local image="$1" expected actual
    expected=$(expected_checksum)
    if [ -z "$expected" ]; then
        echo "ERROR: $CHECKSUM_FILE has no checksum for $IMAGE_FILE_NAME"
        return 1
    fi
    actual=$(sha512sum "$image" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
        echo "ERROR: checksum verification FAILED for $image"
        echo "  expected $expected"
        echo "  actual   $actual"
        return 1
    fi
    echo "✓ Checksum verification passed"
}

if [ ! -f "$BASE_IMAGE" ]; then
    echo "Downloading Debian cloud image..."
    echo "URL: $DEBIAN_URL"

    # Into a .part file, so an interrupted download is never mistaken for a
    # cached image on the next run.
    if ! curl -L -o "$BASE_IMAGE.part" \
        --fail --connect-timeout 30 --max-time 600 \
        --retry 3 --retry-delay 5 --progress-bar \
        "$DEBIAN_URL"; then
        echo "ERROR: Failed to download Debian image"
        rm -f "$BASE_IMAGE.part"
        exit 1
    fi

    echo "Downloading checksum..."
    if ! curl -L -o "$CHECKSUM_FILE" --fail --connect-timeout 30 --max-time 30 \
        --retry 3 --retry-delay 5 "$CHECKSUM_URL"; then
        echo "ERROR: could not download $CHECKSUM_URL - refusing an unverified base image"
        rm -f "$BASE_IMAGE.part" "$CHECKSUM_FILE"
        exit 1
    fi

    if ! verify_base_image "$BASE_IMAGE.part"; then
        rm -f "$BASE_IMAGE.part" "$CHECKSUM_FILE"
        exit 1
    fi
    mv "$BASE_IMAGE.part" "$BASE_IMAGE"
else
    echo "Using cached image: $BASE_IMAGE"
    if [ ! -f "$CHECKSUM_FILE" ]; then
        echo "ERROR: no checksum cached next to it ($CHECKSUM_FILE)"
        echo "  It cannot be verified. Delete it so it is downloaded again:"
        echo "    rm -f $BASE_IMAGE"
        exit 1
    fi
    if ! verify_base_image "$BASE_IMAGE"; then
        echo "  Delete it so it is downloaded again: rm -f $BASE_IMAGE $CHECKSUM_FILE"
        exit 1
    fi
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

# grub.cfg is edited here on the build host rather than with sed inside
# guestfish. The partition hint needs an anchored pattern - "hd0,gpt1" also
# matches the start of "hd0,gpt15" - and getting a backreference through the
# heredoc, guestfish's own escape handling and sed in one piece is not worth
# the risk on the file that decides whether the image boots.
GRUB_CFG="$CACHE_DIR/grub.cfg"
guestfish --ro -a "$WORK_IMAGE" -i download /boot/grub/grub.cfg "$GRUB_CFG"
sed -E -i \
    -e "s/$OLD_UUID/$NEW_UUID/g" \
    -e 's/insmod ext2/insmod btrfs/g' \
    -e "s/(hd0|ahci0),gpt1([^0-9]|\$)/\\1,gpt$ROOT_PARTNUM\\2/g" \
    "$GRUB_CFG"

guestfish -a "$WORK_IMAGE" -i <<EOF
# Update fstab - filesystem type, mount options and UUID
command "sed -i 's/ext4/btrfs/g' /etc/fstab"
command "sed -i 's/errors=remount-ro/compress=zstd,noatime/g' /etc/fstab"
command "sed -i 's/$OLD_UUID/$NEW_UUID/g' /etc/fstab"

# GRUB - filesystem UUID, btrfs module and partition hints, edited above
upload $GRUB_CFG /boot/grub/grub.cfg
command "sed -i 's/$OLD_UUID/$NEW_UUID/g' /etc/default/grub"

# Replace the EFI stub loader config on the ESP
upload $ESP_GRUB_CFG /boot/efi/EFI/debian/grub.cfg
EOF
rm -f "$ESP_GRUB_CFG" "$GRUB_CFG"

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

# Packages are installed from the Debian archive inside the image, together with
# every pending update. They used to be pre-downloaded here with debootstrap,
# which was never offline in practice - apt-get download fetches no dependencies,
# and install.sh needs the network for unstable and backports anyway - and which
# did harm: the chroot saw trixie without trixie-security and the result was
# cached indefinitely, so "dpkg -i" downgraded packages the cloud image already
# had patched, openssh-server among them.
PACKAGE_LIST="$CACHE_DIR/package-list.txt"
printf '%s\n' $PACKAGES > "$PACKAGE_LIST"

# Customize image
echo ""
echo "Customizing image..."

VIRT_CUSTOMIZE_ARGS=(
    --add "$WORK_IMAGE"
    --hostname podman-machine
    --upload "$PACKAGE_LIST:/tmp/package-list.txt"
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
            # A registration secret: readable by nobody else while it exists, and
            # gone as soon as virt-customize has copied it, however the build ends.
            TOKEN_FILE=$(umask 077 && mktemp "$CACHE_DIR/sentinelone-token.XXXXXX")
            trap 'rm -f "$TOKEN_FILE"' EXIT
            printf '%s' "$SENTINELONE_TOKEN" > "$TOKEN_FILE"
            VIRT_CUSTOMIZE_ARGS+=(--upload "$TOKEN_FILE:/tmp/sentinelone-token")
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
    --run-command "rm -rf /tmp/resources /tmp/package-list.txt"
)

virt-customize "${VIRT_CUSTOMIZE_ARGS[@]}"
[ -n "${TOKEN_FILE:-}" ] && rm -f "$TOKEN_FILE"
# Left behind by builds before the token went into a private temporary file.
rm -f "$CACHE_DIR/sentinelone-token"

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
