#!/bin/bash
#
# Podman Machine Image Installation Script
#
# This script runs inside the VM during image build.
# All resources are uploaded to /tmp/resources/ before execution.
#
set -euxo pipefail

echo "========================================"
echo "=== Podman Machine Image Installation ==="
echo "========================================"
echo ""

RESOURCES="/tmp/resources"

echo "=== Installing Podman and dependencies (offline) ==="
cd /tmp/debs
dpkg -i *.deb || true  # May have dependency issues
echo "Fixing dependencies..."
apt-get install -f -y || true  # Fix dependencies
dpkg --configure -a  # Configure all packages

echo ""
echo "=== Verifying critical packages ==="
CRITICAL_PACKAGES="uidmap podman netavark aardvark-dns passt nftables"
MISSING_PACKAGES=""

for pkg in $CRITICAL_PACKAGES; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "WARNING: $pkg not installed, attempting installation from repository..."
        apt-get update -qq
        if ! apt-get install -y $pkg; then
            echo "ERROR: Failed to install $pkg"
            MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
        fi
    fi
done

echo "Verifying package installation..."
for pkg in $CRITICAL_PACKAGES; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "ERROR: Package $pkg is NOT installed!"
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    else
        echo "  ✓ $pkg"
    fi
done

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

if [ -n "$MISSING_PACKAGES" ] || [ -n "$MISSING_BINARIES" ]; then
    echo ""
    echo "=== CRITICAL BUILD FAILURE ==="
    [ -n "$MISSING_PACKAGES" ] && echo "Missing packages:$MISSING_PACKAGES"
    [ -n "$MISSING_BINARIES" ] && echo "Missing binaries:$MISSING_BINARIES"
    exit 1
fi

echo "✓ All critical packages and binaries verified"

echo ""
echo "=== Installing scripts ==="
install -m 755 "$RESOURCES/scripts/ignition-provider.py" /usr/local/sbin/ignition-provider.py
install -m 755 "$RESOURCES/scripts/post-ignition-setup.sh" /usr/local/bin/post-ignition-setup.sh
install -m 755 "$RESOURCES/scripts/podman-machine-ready.sh" /usr/local/bin/podman-machine-ready.sh
install -m 755 "$RESOURCES/scripts/rosetta-activate.sh" /usr/local/bin/rosetta-activate.sh
echo "✓ Scripts installed"

echo ""
echo "=== Installing systemd services ==="
install -m 644 "$RESOURCES/services/ignition-provider.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/post-ignition-setup.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/podman-machine-ready.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/rosetta-activation.service" /etc/systemd/system/

systemctl enable ignition-provider.service
systemctl enable post-ignition-setup.service
systemctl enable podman-machine-ready.service
# Note: rosetta-activation.service is NOT enabled - Ignition will enable it when requested
echo "✓ Services installed"

echo ""
echo "=== Installing configuration files ==="

# Podman configuration
mkdir -p /etc/containers
install -m 644 "$RESOURCES/configs/containers.conf" /etc/containers/containers.conf
install -m 644 "$RESOURCES/configs/storage.conf" /etc/containers/storage.conf
echo "podman-machine" > /etc/containers/podman-machine
echo "✓ Podman configuration installed"

# Sysctl configuration
install -m 644 "$RESOURCES/configs/99-podman.conf" /etc/sysctl.d/99-podman.conf
echo "✓ Sysctl configuration installed"

# Network configuration
mkdir -p /etc/systemd/network
install -m 644 "$RESOURCES/configs/10-vz-nat.network" /etc/systemd/network/10-vz-nat.network
systemctl enable systemd-networkd
systemctl enable systemd-resolved
echo "✓ Network configuration installed"

# SSH configuration
mkdir -p /etc/ssh/sshd_config.d
install -m 644 "$RESOURCES/configs/podman-machine.conf" /etc/ssh/sshd_config.d/podman-machine.conf

# Disable systemd-ssh-generator (Debian 13 creates vsock/unix sockets, we need TCP)
mkdir -p /etc/systemd/system-generators
ln -sf /dev/null /etc/systemd/system-generators/systemd-ssh-generator
ssh-keygen -A
systemctl enable ssh.service
echo "✓ SSH configuration installed"

# User delegation for rootless containers
mkdir -p /etc/systemd/system/user@.service.d/
install -m 644 "$RESOURCES/configs/delegate.conf" /etc/systemd/system/user@.service.d/delegate.conf
echo "✓ User delegation configured"

# Docker compatibility symlink for SentinelOne
ln -sf /var/lib/containers/storage /var/lib/docker
echo "✓ Docker compatibility symlink created"

# Enable podman.socket for root (rootful mode support)
systemctl enable podman.socket
echo "✓ Podman rootful socket enabled"

# DEBUG_BUILD support
if [ -f /tmp/debug-build-marker ]; then
    echo ""
    echo "=== DEBUG BUILD: Setting root password ==="
    echo "root:podman" | chpasswd
    echo "✓ Root password set to 'podman'"

    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/50-console-logging.conf << 'EOF'
[Manager]
LogTarget=console
LogLevel=debug
ShowStatus=yes
EOF

    if [ -f /etc/default/grub ]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="console=hvc0 systemd.log_level=debug systemd.log_target=console /' /etc/default/grub
        update-grub 2>/dev/null || true
    fi
    echo "✓ Debug logging enabled"
    rm -f /tmp/debug-build-marker
else
    echo ""
    echo "=== Production build ==="
    passwd -l root 2>/dev/null || true
    echo "✓ Root account locked"
fi

# SentinelOne installation
if [ -f /tmp/s1.deb ]; then
    echo ""
    echo "=== Installing SentinelOne ==="
    dpkg -i /tmp/s1.deb
    echo "✓ SentinelOne installed"

    if [ -f /tmp/sentinelone-token ]; then
        echo "Setting up SentinelOne registration token..."
        mkdir -p /etc/sentinelone
        cp /tmp/sentinelone-token /etc/sentinelone/registration-token
        chmod 600 /etc/sentinelone/registration-token
        echo "✓ Registration token saved"
        rm -f /tmp/sentinelone-token
    fi

    rm -f /tmp/s1.deb
fi

echo ""
echo "========================================"
echo "=== Installation complete ==="
echo "========================================"
