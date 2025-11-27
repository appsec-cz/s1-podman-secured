#!/bin/bash
#
# Improved Build Script with Production Fixes
# - Timeout handling
# - SentinelOne token support
# - Verbose output
# - Error handling improvements
#
set -euo pipefail

# Configuration
ARCH="${ARCH:-$(uname -m)}"
IMAGE_SIZE="${IMAGE_SIZE:-10G}"
IMAGE_NAME="${IMAGE_NAME:-podman-debian}"
INSTALL_SENTINELONE="${INSTALL_SENTINELONE:-1}"
SENTINELONE_TOKEN="${SENTINELONE_TOKEN:-}"  # Registration token
VERBOSE="${VERBOSE:-0}"  # Verbose mode
DEBUG_BUILD="${DEBUG_BUILD:-0}"  # Debug build (enables root password, verbose logging)

# Directories
CACHE_DIR="cache"
OUTPUT_DIR="output"
INSTALL_DIR="install"
DEBS_DIR="debs"

mkdir -p "$CACHE_DIR" "$OUTPUT_DIR"

echo "========================================"
echo "Building: $IMAGE_NAME (Debian 13 $ARCH)"
echo "========================================"
echo ""

# Architecture mapping for Debian
case "$ARCH" in
    aarch64|arm64)
        DEBIAN_ARCH="arm64"
        ;;
    x86_64|amd64)
        DEBIAN_ARCH="amd64"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
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

    # NEW: Timeout and retry logic
    if ! curl -L -o "$BASE_IMAGE" \
        --fail \
        --connect-timeout 30 \
        --max-time 600 \
        --retry 3 \
        --retry-delay 5 \
        --progress-bar \
        "$DEBIAN_URL"; then
        echo "ERROR: Failed to download Debian image"
        rm -f "$BASE_IMAGE"
        exit 1
    fi

    echo "Download complete!"

    # NEW: Checksum verification
    echo "Downloading checksum..."
    if ! curl -L -o "$CHECKSUM_FILE" \
        --fail \
        --connect-timeout 30 \
        --max-time 30 \
        "$CHECKSUM_URL"; then
        echo "WARNING: Failed to download checksum, skipping verification"
    else
        echo "Verifying checksum..."

        # Extract expected checksum for our architecture
        EXPECTED_CHECKSUM=$(grep "debian-13-generic-${DEBIAN_ARCH}.qcow2" "$CHECKSUM_FILE" | awk '{print $1}')

        if [ -z "$EXPECTED_CHECKSUM" ]; then
            echo "WARNING: Could not find checksum for debian-13-generic-${DEBIAN_ARCH}.qcow2"
            echo "Skipping verification"
        else
            # Calculate actual checksum
            ACTUAL_CHECKSUM=$(sha512sum "$BASE_IMAGE" | awk '{print $1}')

            if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
                echo "✓ Checksum verification passed"
            else
                echo "ERROR: Checksum verification FAILED"
                echo "  Expected: $EXPECTED_CHECKSUM"
                echo "  Got:      $ACTUAL_CHECKSUM"
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

    # Create temporary container to download packages
    # Use cache dir instead of /tmp to avoid permission/mount issues
    TEMP_CONTAINER="$CACHE_DIR/debootstrap-temp"
    rm -rf "$TEMP_CONTAINER"  # Clean up if exists
    mkdir -p "$TEMP_CONTAINER"

    # Use debootstrap to create minimal Debian 13 environment
    if ! command -v debootstrap &> /dev/null; then
        echo "ERROR: debootstrap not installed"
        echo "Run: sudo apt-get install debootstrap"
        exit 1
    fi

    echo "Creating temporary Debian 13 environment..."
    sudo debootstrap --variant=minbase trixie "$TEMP_CONTAINER" http://deb.debian.org/debian

    # Mount necessary filesystems for chroot
    echo "Setting up chroot environment..."
    sudo mount --bind /dev "$TEMP_CONTAINER/dev"
    sudo mount --bind /proc "$TEMP_CONTAINER/proc"
    sudo mount --bind /sys "$TEMP_CONTAINER/sys"

    # Download packages in chroot
    echo "Downloading required packages..."
    sudo chroot "$TEMP_CONTAINER" /bin/bash -c "
        apt-get update
        cd /tmp
        apt-get download \
            podman \
            conmon \
            containernetworking-plugins \
            netavark \
            aardvark-dns \
            slirp4netns \
            passt \
            uidmap \
            fuse-overlayfs \
            crun \
            openssh-server \
            socat \
            dbus-user-session \
            systemd-container \
            iptables \
            nftables \
            iproute2 \
            qemu-user \
            qemu-user-binfmt \
            podman-docker \
            cifs-utils \
            nfs-common \
            procps \
            chrony 2>/dev/null || true
    "

    # Copy downloaded packages
    sudo cp "$TEMP_CONTAINER"/tmp/*.deb "$DEBS_DIR/" 2>/dev/null || true
    sudo chown -R $(id -u):$(id -g) "$DEBS_DIR"

    # Verify packages were actually downloaded
    PKG_COUNT=$(ls -1 "$DEBS_DIR"/*.deb 2>/dev/null | wc -l)
    if [ "$PKG_COUNT" -eq 0 ]; then
        echo "ERROR: Package download failed - no .deb files found in $DEBS_DIR"
        echo "Check the apt-get download command output above for errors"
        exit 1
    fi
    echo "✓ Downloaded $PKG_COUNT packages"

    # Cleanup - unmount first!
    sudo umount "$TEMP_CONTAINER/dev" 2>/dev/null || true
    sudo umount "$TEMP_CONTAINER/proc" 2>/dev/null || true
    sudo umount "$TEMP_CONTAINER/sys" 2>/dev/null || true
    sudo rm -rf "$TEMP_CONTAINER"
else
    echo ""
    echo "Using cached packages in $DEBS_DIR/"

    # Verify cached packages exist
    PKG_COUNT=$(ls -1 "$DEBS_DIR"/*.deb 2>/dev/null | wc -l)
    if [ "$PKG_COUNT" -eq 0 ]; then
        echo "ERROR: No cached packages found in $DEBS_DIR"
        echo "Run 'make clean' and rebuild to download packages"
        exit 1
    fi
    echo "✓ Using $PKG_COUNT cached packages"
fi

# Create install script
echo "Creating install script..."
cat > "$CACHE_DIR/install.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
set -euxo pipefail  # CHANGED: Added -u and -x for verbose output

echo "========================================"
echo "=== Podman Machine Image Installation ==="
echo "========================================"
echo ""

echo "=== Installing Podman and dependencies (offline) ==="
cd /tmp/debs
dpkg -i *.deb || true  # May have dependency issues
echo "Fixing dependencies..."
apt-get install -f -y || true  # Fix dependencies
dpkg --configure -a  # Configure all packages

echo ""
echo "=== Verifying critical packages ==="
# Ensure critical packages are installed (with network fallback)
# nftables is required by netavark for container networking
CRITICAL_PACKAGES="uidmap podman netavark aardvark-dns passt nftables"
MISSING_PACKAGES=""

for pkg in $CRITICAL_PACKAGES; do
    # Use dpkg-query for reliable package status checking
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "WARNING: $pkg not installed, attempting installation from repository..."
        apt-get update -qq
        if ! apt-get install -y $pkg; then
            echo "ERROR: Failed to install $pkg"
            MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
        fi
    fi
done

# Verify packages are actually installed after installation attempts
echo "Verifying package installation..."
for pkg in $CRITICAL_PACKAGES; do
    # Use dpkg-query for reliable package status checking
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "ERROR: Package $pkg is NOT installed!"
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    else
        echo "  ✓ $pkg"
    fi
done

# Check critical binaries
echo ""
echo "Verifying critical binaries..."
CRITICAL_BINARIES="newuidmap newgidmap podman pasta"
MISSING_BINARIES=""

for binary in $CRITICAL_BINARIES; do
    if ! which $binary > /dev/null 2>&1; then
        echo "ERROR: Binary '$binary' not found in PATH!"
        MISSING_BINARIES="$MISSING_BINARIES $binary"
    else
        echo "  ✓ $binary ($(which $binary))"
    fi
done

# Fail the build if any critical packages or binaries are missing
if [ -n "$MISSING_PACKAGES" ] || [ -n "$MISSING_BINARIES" ]; then
    echo ""
    echo "=========================================="
    echo "=== CRITICAL BUILD FAILURE ==="
    echo "=========================================="
    [ -n "$MISSING_PACKAGES" ] && echo "Missing packages:$MISSING_PACKAGES"
    [ -n "$MISSING_BINARIES" ] && echo "Missing binaries:$MISSING_BINARIES"
    echo ""
    echo "The image build cannot continue without these critical components."
    echo "Please ensure all required packages are available in the Debian repositories"
    echo "or fix the offline package download process."
    echo ""
    exit 1
fi

echo "✓ All critical packages and binaries verified"

echo ""
echo "=== Configuring multi-architecture support ==="
# Enable binfmt_misc for running foreign architecture binaries via QEMU
# This allows ARM64 image to run x86_64 containers (and vice versa)
# Note: systemd-binfmt.service is statically enabled, manual enable not needed

# Verify qemu-user-static is available for cross-architecture support
CURRENT_ARCH=$(uname -m)
case "$CURRENT_ARCH" in
    aarch64|arm64)
        if [ -f /usr/bin/qemu-x86_64-static ]; then
            echo "✓ x86_64 emulation available (can run amd64 containers on arm64)"
        fi
        ;;
    x86_64|amd64)
        if [ -f /usr/bin/qemu-aarch64-static ]; then
            echo "✓ ARM64 emulation available (can run arm64 containers on amd64)"
        fi
        ;;
esac
echo "✓ Multi-arch support configured"

echo ""
echo "=== Installing Ignition Provider ==="
install -m 755 /tmp/ignition-provider.py /usr/local/sbin/ignition-provider.py

# Create ignition-provider.service inline
cat > /etc/systemd/system/ignition-provider.service << 'IGNSERVEOF'
[Unit]
Description=Ignition Configuration Provider for Podman Machine
DefaultDependencies=no
Before=network-pre.target
Before=ssh.service
Before=systemd-user-sessions.service
After=systemd-remount-fs.service
After=systemd-tmpfiles-setup.service
After=systemd-modules-load.service
Wants=network-pre.target
ConditionPathExists=!/var/lib/ignition-provider-complete

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /usr/local/sbin/ignition-provider.py
ExecStartPost=/bin/touch /var/lib/ignition-provider-complete
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
RequiredBy=ssh.service
IGNSERVEOF

systemctl enable ignition-provider.service
echo "✓ Ignition provider installed"

echo ""
echo "=== Configuring post-Ignition setup ==="
# CRITICAL: Core user will be created by Ignition with dynamic UID
# This service runs after Ignition creates the user to set up additional config
cat > /usr/local/bin/post-ignition-setup.sh << 'POSTIGNEOF'
#!/bin/bash
# Post-Ignition setup for Podman machine
set -e

logger "post-ignition-setup: Starting"

# Wait for Ignition to complete
if [ ! -f /var/lib/ignition-provider-complete ]; then
    logger "ERROR: Ignition not completed"
    exit 1
fi

# Find the user created by Ignition (should be core)
USERNAME="core"

if ! id "$USERNAME" &>/dev/null; then
    logger "ERROR: User $USERNAME not found (Ignition should have created it)"
    exit 1
fi

logger "post-ignition-setup: Configuring for user $USERNAME"

# Get user info
USER_UID=$(id -u "$USERNAME")
USER_GID=$(id -g "$USERNAME")
USER_HOME=$(eval echo "~$USERNAME")

logger "post-ignition-setup: UID=$USER_UID GID=$USER_GID HOME=$USER_HOME"

# Set up sudoers
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME
chmod 0440 /etc/sudoers.d/$USERNAME
logger "post-ignition-setup: Sudoers configured"

# Set up subuid/subgid for rootless containers
sed -i "/^$USERNAME:/d" /etc/subuid /etc/subgid 2>/dev/null || true
echo "$USERNAME:100000:65536" >> /etc/subuid
echo "$USERNAME:100000:65536" >> /etc/subgid
logger "post-ignition-setup: subuid/subgid configured"

# Enable lingering (if not already done by Ignition)
if [ ! -f "/var/lib/systemd/linger/$USERNAME" ]; then
    mkdir -p /var/lib/systemd/linger
    touch "/var/lib/systemd/linger/$USERNAME"
    logger "post-ignition-setup: Linger enabled"
fi

# Enable podman.socket for user (if not already done by Ignition)
SOCKET_WANTS="$USER_HOME/.config/systemd/user/sockets.target.wants"
if [ ! -L "$SOCKET_WANTS/podman.socket" ]; then
    mkdir -p "$SOCKET_WANTS"
    ln -sf /usr/lib/systemd/user/podman.socket "$SOCKET_WANTS/podman.socket"
    chown -R $USERNAME:$USERNAME "$USER_HOME/.config"
    logger "post-ignition-setup: podman.socket enabled"
fi

# Enable SSH config with StreamLocal forwarding (if not exists)
if [ ! -f /etc/ssh/sshd_config.d/streamlocal.conf ]; then
    cat > /etc/ssh/sshd_config.d/streamlocal.conf << 'SSHEOF'
# CRITICAL: Allow SSH socket forwarding for Podman Desktop
AllowStreamLocalForwarding yes
AllowTcpForwarding yes
StreamLocalBindUnlink yes
SSHEOF
    logger "post-ignition-setup: SSH StreamLocal forwarding enabled"
    systemctl reload ssh.service 2>/dev/null || true
fi

# Create user-specific containers.conf
USER_CONTAINERS_DIR="$USER_HOME/.config/containers"
mkdir -p "$USER_CONTAINERS_DIR"
cat > "$USER_CONTAINERS_DIR/containers.conf" << 'USERCONTEOF'
[containers]
netns = "bridge"
pids_limit = 0

[engine]
machine_enabled = true
USERCONTEOF
chown -R $USER_UID:$USER_GID "$USER_CONTAINERS_DIR"
logger "post-ignition-setup: User containers.conf created"

# Configure docker.sock symlink with correct UID
# Check if rootful mode (Ignition may have set /etc/tmpfiles.d/podman-docker.conf)
if [ -f /etc/tmpfiles.d/podman-docker.conf ]; then
    # Podman machine init already created the config - verify and update if needed
    if grep -q "/run/podman/podman.sock" /etc/tmpfiles.d/podman-docker.conf; then
        logger "post-ignition-setup: Rootful mode detected (docker.sock -> /run/podman/podman.sock)"
    elif grep -q "/run/user/" /etc/tmpfiles.d/podman-docker.conf; then
        # Update with correct UID if it was set with wrong UID
        echo "L+  /run/docker.sock   -    -    -     -   /run/user/$USER_UID/podman/podman.sock" \
            > /etc/tmpfiles.d/podman-docker.conf
        logger "post-ignition-setup: Updated docker.sock symlink for UID $USER_UID"
    fi
else
    # Create default rootless config
    echo "L+  /run/docker.sock   -    -    -     -   /run/user/$USER_UID/podman/podman.sock" \
        > /etc/tmpfiles.d/podman-docker.conf
    logger "post-ignition-setup: Created docker.sock symlink for UID $USER_UID"
fi

# Apply tmpfiles configuration
systemd-tmpfiles --create /etc/tmpfiles.d/podman-docker.conf 2>/dev/null || true
logger "post-ignition-setup: docker.sock symlink applied"

logger "post-ignition-setup: Completed successfully"
POSTIGNEOF

chmod +x /usr/local/bin/post-ignition-setup.sh

cat > /etc/systemd/system/post-ignition-setup.service << 'POSTIGNSVC'
[Unit]
Description=Post-Ignition Setup for Podman Machine
After=ignition-provider.service
Requires=ignition-provider.service
Before=podman-machine-ready.service
ConditionPathExists=/var/lib/ignition-provider-complete

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/post-ignition-setup.sh
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
RequiredBy=podman-machine-ready.service
POSTIGNSVC

systemctl enable post-ignition-setup.service
echo "✓ Post-Ignition setup service installed"

# DEBUG_BUILD marker file - will be checked by install script
# This is set by the outer build.sh script
if [ -f /tmp/debug-build-marker ]; then
    echo ""
    echo "=== DEBUG BUILD: Setting root password ==="
    # Set root password to 'podman' for serial console access
    echo "root:podman" | chpasswd
    echo "✓ Root password set to 'podman' (DEBUG BUILD ONLY)"

    echo ""
    echo "=== DEBUG BUILD: Configuring verbose logging ==="
    # Enable all systemd messages to serial console
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/50-console-logging.conf << 'CONSOLEEOF'
[Manager]
# Forward all messages to console for debugging
LogTarget=console
LogLevel=debug
ShowStatus=yes
CONSOLEEOF

    # Enable kernel and systemd console output via GRUB
    if [ -f /etc/default/grub ]; then
        # Add console=hvc0 to kernel command line for serial console output
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="console=hvc0 systemd.log_level=debug systemd.log_target=console /' /etc/default/grub
        update-grub 2>/dev/null || true
    fi

    echo "✓ Verbose serial console logging enabled (DEBUG BUILD ONLY)"
    rm -f /tmp/debug-build-marker
else
    echo ""
    echo "=== Production build: No root password set ==="
    # Lock root account for security
    passwd -l root 2>/dev/null || true
    echo "✓ Root account locked (production build)"
fi

echo ""
echo "=== Configuring SSH ==="
# NOTE: User home directories and SSH keys will be created by Ignition provider
# with correct ownership based on dynamically assigned UID

cat > /etc/ssh/sshd_config.d/podman-machine.conf << 'SSHEOF'
# CRITICAL: Listen on TCP port 22 (required for Podman Desktop)
# Debian 13's systemd-ssh-generator creates only vsock/unix by default
# We need traditional TCP socket for port forwarding to work
Port 22
ListenAddress 0.0.0.0

# Pubkey authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Password authentication (backup)
PasswordAuthentication yes
PermitEmptyPasswords no

# PAM and environment
UsePAM yes
AcceptEnv LANG LC_*

# SFTP subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
SSHEOF

# CRITICAL FIX: Disable systemd-ssh-generator completely
# Debian 13's generator only creates vsock/unix sockets, not TCP
# We need TCP port 22 for Podman Desktop SSH forwarding
mkdir -p /etc/systemd/system-generators
ln -sf /dev/null /etc/systemd/system-generators/systemd-ssh-generator
echo "✓ systemd-ssh-generator disabled"

# Generate SSH host keys (sshd-keygen.service won't run)
ssh-keygen -A
echo "✓ SSH host keys generated"

# Enable SSH service (will use config from sshd_config.d above)
systemctl enable ssh.service
echo "✓ SSH service enabled"

echo ""
echo "=== Configuring user namespaces ==="
# NOTE: User namespaces (subuid/subgid) will be configured by post-ignition-setup
# after Ignition creates the user with correct UID
echo "✓ User namespace setup deferred to post-ignition-setup.service"

echo ""
echo "=== Configuring network and sysctl ==="

# CRITICAL: Enable network interfaces for Podman AppleHV
# Debian cloud image doesn't auto-configure network without cloud-init
# We need to enable DHCP on the network interface
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/10-vz-nat.network << 'NETEOF'
[Match]
Name=en*

[Network]
DHCP=yes
DNS=192.168.127.1

[DHCPv4]
UseDNS=yes

[Link]
RequiredForOnline=yes
NETEOF

# Enable systemd-networkd (handles DHCP client)
systemctl enable systemd-networkd
systemctl enable systemd-resolved
echo "✓ Network configured (DHCP enabled)"

# Configure sysctl for container networking
cat > /etc/sysctl.d/99-podman.conf << 'SYSCTLEOF'
# Enable IP forwarding for container networking
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1

# Bridge netfilter for iptables
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

# User namespaces
kernel.unprivileged_userns_clone = 1

# Increase inotify limits for containers (match Fedora CoreOS)
fs.inotify.max_user_instances = 524288
fs.inotify.max_user_watches = 524288
SYSCTLEOF
echo "✓ Network and sysctl configured"

echo ""
echo "=== Configuring cgroups v2 ==="
# Debian 13 uses cgroups v2 by default - no GRUB modification needed
# Verify it's enabled via systemd (will be active at boot)
echo "✓ Cgroups v2 (default in Debian 13, no GRUB modification needed)"

echo ""
echo "=== Configuring Podman ==="
# Create Podman storage configuration
mkdir -p /etc/containers

# CRITICAL: Create podman-machine marker file
# This file is required for Podman Desktop to detect this as a Podman machine
echo "podman-machine" > /etc/containers/podman-machine
echo "✓ Podman machine marker file created"

# Create global containers.conf with Podman machine defaults
# These settings match Fedora CoreOS podman machine configuration
cat > /etc/containers/containers.conf << 'CONTAINERSEOF'
[containers]
# Bridge networking for better compatibility
netns = "bridge"
# No PID limit (required for some workloads)
pids_limit = 0
# Use host's DNS via gateway
dns_servers = ["192.168.127.1"]

[engine]
# Mark this as a Podman machine
machine_enabled = true
# Use crun as default runtime (faster than runc)
runtime = "crun"

[network]
# Use netavark for networking (modern CNI replacement)
network_backend = "netavark"
CONTAINERSEOF
echo "✓ Global containers.conf created"

cat > /etc/containers/storage.conf << 'STORAGEEOF'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options]
# Enable native overlay diff for better performance
mount_program = "/usr/bin/fuse-overlayfs"

[storage.options.overlay]
# Increase overlay mount limit
mountopt = "nodev,metacopy=on"
STORAGEEOF
echo "✓ Podman storage configured"

# Configure Podman for rootless operation
mkdir -p /etc/systemd/system/user@.service.d/
cat > /etc/systemd/system/user@.service.d/delegate.conf << 'EOF'
[Service]
Delegate=yes
EOF

# NOTE: Linger and podman.socket enablement will be done by post-ignition-setup
# after Ignition creates the user with correct UID
echo "✓ Podman user delegation configured (linger/socket deferred to post-ignition-setup)"

# Enable podman.socket for root (rootful mode support)
# This creates /run/podman/podman.sock when started
systemctl enable podman.socket
echo "✓ Podman rootful socket enabled (for rootful mode support)"

# NEW: SentinelOne with token support
if [ -f /tmp/s1.deb ]; then
    echo ""
    echo "=== Installing SentinelOne ==="
    dpkg -i /tmp/s1.deb
    echo "✓ SentinelOne installed"

    # NEW: Token registration
    if [ -f /tmp/sentinelone-token ]; then
        echo "Setting up SentinelOne registration token..."
        mkdir -p /etc/sentinelone
        cp /tmp/sentinelone-token /etc/sentinelone/registration-token
        chmod 600 /etc/sentinelone/registration-token
        echo "✓ Registration token saved (will be used by Ignition provider)"
        rm -f /tmp/sentinelone-token
    fi

    rm -f /tmp/s1.deb
fi

echo ""
echo "=== Creating ready service ==="
# NEW: Improved ready service with timeouts
cat > /etc/systemd/system/podman-machine-ready.service << 'EOF'
[Unit]
Description=Podman Machine Ready Reporter
# Run after SSH and user sessions are ready
After=sshd.socket sshd.service ssh.service
After=ignition-provider.service post-ignition-setup.service
After=systemd-user-sessions.service
After=network-online.target
Wants=network-online.target
# Ignition must complete before we can signal ready
Requires=ignition-provider.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/podman-machine-ready.sh
StandardOutput=journal+console
StandardError=journal+console
# Retry a few times if vsock connection fails
Restart=on-failure
RestartSec=2
StartLimitInterval=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/podman-machine-ready.sh << 'EOF'
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
EOF

chmod +x /usr/local/bin/podman-machine-ready.sh
systemctl enable podman-machine-ready.service
echo "✓ Ready service created"

echo ""
echo "========================================"
echo "=== Installation complete ==="
echo "========================================"
INSTALL_SCRIPT

chmod +x "$CACHE_DIR/install.sh"

# Customize image
echo ""
echo "Customizing image..."

VIRT_CUSTOMIZE_ARGS=(
    --add "$WORK_IMAGE"
    --hostname podman-machine
    --copy-in "$DEBS_DIR:/tmp/"
    --upload "$CACHE_DIR/install.sh:/tmp/install.sh"
    --upload "ignition-provider.py:/tmp/ignition-provider.py"
)

# Verbose mode support
if [ "$VERBOSE" = "1" ]; then
    VIRT_CUSTOMIZE_ARGS+=(--verbose)
fi

# Debug build support - creates marker file that install script checks
if [ "$DEBUG_BUILD" = "1" ]; then
    echo "DEBUG BUILD enabled - root password and verbose logging will be configured"
    touch "$CACHE_DIR/debug-build-marker"
    VIRT_CUSTOMIZE_ARGS+=(--upload "$CACHE_DIR/debug-build-marker:/tmp/debug-build-marker")
fi

# Add SentinelOne .deb if available
if [ "$INSTALL_SENTINELONE" = "1" ]; then
    S1_DEB=$(find "$INSTALL_DIR" -name "SentinelAgent*.deb" 2>/dev/null | head -n1)
    if [ -n "$S1_DEB" ] && [ -f "$S1_DEB" ]; then
        echo "Found SentinelOne package: $S1_DEB"
        VIRT_CUSTOMIZE_ARGS+=(--upload "$S1_DEB:/tmp/s1.deb")

        # NEW: Upload token if provided
        if [ -n "$SENTINELONE_TOKEN" ]; then
            echo "SentinelOne registration token provided"
            echo -n "$SENTINELONE_TOKEN" > "$CACHE_DIR/sentinelone-token"
            VIRT_CUSTOMIZE_ARGS+=(--upload "$CACHE_DIR/sentinelone-token:/tmp/sentinelone-token")
        else
            echo "WARNING: No SENTINELONE_TOKEN provided - agent will not register automatically"
        fi
    else
        echo "No SentinelOne package found in $INSTALL_DIR"
    fi
fi

# Run install script (save log in /var/log for later extraction)
# CRITICAL: Use 'set -o pipefail' to ensure errors from install.sh propagate through tee
VIRT_CUSTOMIZE_ARGS+=(
    --run-command "set -o pipefail && bash -x /tmp/install.sh 2>&1 | tee /var/log/image-build-install.log"
    --run-command "rm -rf /tmp/install.sh /tmp/debs /tmp/ignition-provider.py"
)

# Run virt-customize
virt-customize "${VIRT_CUSTOMIZE_ARGS[@]}"

# Extract and display install log if verbose mode or if user wants to see it
if [ "$VERBOSE" = "1" ]; then
    echo ""
    echo "========================================"
    echo "=== Install Script Output ==="
    echo "========================================"
    if virt-cat -a "$WORK_IMAGE" /var/log/image-build-install.log 2>/dev/null; then
        echo "========================================"
    else
        echo "WARNING: Could not extract install log"
    fi
fi

# Create output format
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
if [ -n "$SENTINELONE_TOKEN" ]; then
    echo "✓ SentinelOne token configured - agent will register automatically"
else
    echo "⚠ No SentinelOne token - agent installed but not registered"
    echo "  Set SENTINELONE_TOKEN environment variable to enable auto-registration"
fi
echo ""
