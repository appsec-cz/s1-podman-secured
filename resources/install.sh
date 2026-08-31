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
echo "=== Verifying installed packages ==="
# dpkg -i on the downloaded set leaves packages unconfigured whenever one of their
# dependencies is not in the set, and the 'apt-get install -f' above then resolves
# that by REMOVING them. That silently cost the image crun (the OCI runtime named
# in containers.conf), chrony, cifs-utils and nfs-common - the build reported
# success because only a handful of packages were ever verified. Every package
# build.sh intended to install is now repaired and verified.
if [ ! -f /tmp/debs/package-list.txt ]; then
    echo "ERROR: /tmp/debs/package-list.txt is missing - build.sh must ship it"
    exit 1
fi
PACKAGES=$(grep -vE '^[[:space:]]*(#|$)' /tmp/debs/package-list.txt | tr '\n' ' ')
echo "Intended packages: $PACKAGES"

MISSING_PACKAGES=""
APT_UPDATED=0

for pkg in $PACKAGES; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "WARNING: $pkg not installed, attempting installation from repository..."
        if [ "$APT_UPDATED" = "0" ]; then
            apt-get update -qq
            APT_UPDATED=1
        fi
        if ! apt-get install -y $pkg; then
            echo "ERROR: Failed to install $pkg"
        fi
    fi
done

echo "Verifying package installation..."
for pkg in $PACKAGES; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "ERROR: Package $pkg is NOT installed!"
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    else
        echo "  ✓ $pkg"
    fi
done

echo ""
echo "Verifying critical binaries..."
CRITICAL_BINARIES="newuidmap newgidmap podman pasta crun"
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
echo "=== Upgrading the container stack from unstable ==="
# Debian stable ships podman 5.4.2 and never moves; trixie-backports carries no
# container packages at all, only the kernel. Unstable has podman 5.8.x, and the
# upgrade is unusually contained: podman, crun, netavark, aardvark-dns and conmon,
# with no libc or systemd pulled along.
#
# Unstable gets no security support, which is a real cost for this image. It is
# limited as tightly as apt allows: unstable is pinned below stable, so nothing
# else drifts, and only these five packages are taken from it explicitly.
cat > /etc/apt/sources.list.d/containers-unstable.list <<'SOURCES'
deb http://deb.debian.org/debian sid main
SOURCES
cat > /etc/apt/preferences.d/containers-unstable <<'PINNING'
Package: *
Pin: release a=unstable
Pin-Priority: 100
PINNING

apt-get update -qq
CONTAINER_STACK="podman crun netavark aardvark-dns conmon"
echo "Before: $(dpkg-query -W -f='${Version}' podman 2>/dev/null)"

if apt-get install -y -t sid $CONTAINER_STACK; then
    for pkg in $CONTAINER_STACK; do
        printf '  %s %s\n' "$pkg" "$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
    done
    echo "✓ Container stack upgraded from unstable"
else
    echo "WARNING: could not upgrade the container stack, keeping the stable versions"
fi

# The pin stays in the image on purpose: without it a later apt-get upgrade in
# the running machine would have no idea these packages came from unstable and
# would happily pull the rest of unstable along with them.
apt-get update -qq

echo ""
echo "=== Installing a newer kernel from backports ==="
# Debian stable ships 6.12; backports carries the kernel from the next release.
# The image keeps exactly one kernel: the new one is installed, the stable one is
# purged, so this costs nothing in size. Installing a kernel regenerates
# /boot/grub/grub.cfg, which is why build.sh verifies the bootloader again after
# this script has run.
#
# The trade this makes: backports is not covered by Debian's security team, so
# kernel fixes arrive when the backport is refreshed rather than on the security
# team's schedule.
DEB_ARCH=$(dpkg --print-architecture)

# Kernel packages come in several parts, and the naming differs between the
# stable and the backports kernel: linux-image-<ver>, its -unsigned counterpart,
# and on newer kernels linux-modules-<ver> and linux-binary-<ver>. Match on the
# version instead of guessing package names, or the old kernel's 169 MB
# -unsigned package stays behind.
kernel_packages() {
    # dpkg-query exits non-zero as soon as one of the patterns matches nothing,
    # and the stable kernel has no linux-modules-* or linux-binary-* package.
    # With 'set -o pipefail' that status propagates and set -e kills the script
    # right after the assignment - which is exactly how the first attempt failed.
    dpkg-query -Wf '${Package}\n' \
        'linux-image-[0-9]*' 'linux-modules-[0-9]*' 'linux-binary-[0-9]*' 2>/dev/null | sort -u || true
}

OLD_KERNEL_PKGS=$(kernel_packages | tr '\n' ' ')
echo "Kernel packages before: ${OLD_KERNEL_PKGS:-none}"

echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list
apt-get update -qq

if apt-get install -y -t trixie-backports "linux-image-$DEB_ARCH"; then
    # Highest version wins; ignore the -unsigned variants when picking it.
    NEW_VERSION=$(kernel_packages | grep '^linux-image-' | grep -v -- '-unsigned$' \
        | sed 's/^linux-image-//' | sort -V | tail -1 || true)

    if [ -z "$NEW_VERSION" ]; then
        echo "ERROR: no versioned kernel package after the backports install"
        exit 1
    fi
    echo "Kernel after: $NEW_VERSION"

    for pkg in $(kernel_packages); do
        case "$pkg" in
            *"$NEW_VERSION"*) ;;
            *) echo "Removing superseded kernel package $pkg"
               apt-get purge -y "$pkg" ;;
        esac
    done
    apt-get autoremove -y --purge

    REMAINING=$(kernel_packages | tr '\n' ' ')
    echo "Kernel packages after: $REMAINING"
    case "$REMAINING" in
        *"$NEW_VERSION"*) echo "✓ Kernel replaced with the backports build" ;;
        *) echo "ERROR: the backports kernel is not installed after cleanup"; exit 1 ;;
    esac

    VMLINUZ_COUNT=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l || true)
    if [ "$VMLINUZ_COUNT" -ne 1 ]; then
        echo "ERROR: expected exactly one kernel in /boot, found $VMLINUZ_COUNT"
        ls -la /boot/vmlinuz-* 2>/dev/null || true
        exit 1
    fi
else
    # Not fatal: an image on the stable kernel still works, and failing the whole
    # build because a backport moved would be worse than shipping 6.12.
    echo "WARNING: could not install the backports kernel, keeping ${OLD_KERNEL_PKGS:-the stable kernel}"
fi

rm -f /etc/apt/sources.list.d/backports.list
apt-get update -qq

echo ""
echo "=== Installing scripts ==="
install -m 755 "$RESOURCES/scripts/ignition-provider.py" /usr/local/sbin/ignition-provider.py
install -m 755 "$RESOURCES/scripts/post-ignition-setup.sh" /usr/local/bin/post-ignition-setup.sh
install -m 755 "$RESOURCES/scripts/podman-machine-ready.sh" /usr/local/bin/podman-machine-ready.sh
# Named without the .sh so it reads as a command when run by hand, which is most
# of what it is for.
install -m 755 "$RESOURCES/scripts/machine-diagnostics.sh" /usr/local/bin/podman-machine-diagnostics
install -m 755 "$RESOURCES/scripts/machine-health.sh" /usr/local/bin/podman-machine-health
install -m 755 "$RESOURCES/scripts/rosetta-activate.sh" /usr/local/bin/rosetta-activate.sh
echo "✓ Scripts installed"

echo ""
echo "=== Installing systemd services ==="
install -m 644 "$RESOURCES/services/ignition-provider.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/post-ignition-setup.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/podman-machine-ready.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/rosetta-activation.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/podman-machine-health.service" /etc/systemd/system/
install -m 644 "$RESOURCES/services/podman-machine-health.timer" /etc/systemd/system/

systemctl enable ignition-provider.service
systemctl enable post-ignition-setup.service
systemctl enable podman-machine-ready.service
systemctl enable podman-machine-health.timer
# Note: rosetta-activation.service is NOT enabled - Ignition will enable it when requested
echo "✓ Services installed"

echo ""
echo "=== Installing configuration files ==="

# Podman configuration
mkdir -p /etc/containers
install -m 644 "$RESOURCES/configs/containers.conf" /etc/containers/containers.conf
install -m 644 "$RESOURCES/configs/storage.conf" /etc/containers/storage.conf
echo "podman-machine" > /etc/containers/podman-machine

# Podman 6 mounts the host's ~/.config/containers over /etc/containers inside the
# VM (etc-containers.mount in its Ignition config), which hides everything we put
# in /etc/containers: storage.conf (the driver silently falls back to overlay) and
# containers.conf (runtime, netns and dns settings never apply). /usr/share/containers
# is not shadowed and is read as the base configuration, so both files go there too.
# Note: a containers.conf.d drop-in under /usr/share is NOT read - it has to be the
# file itself.
mkdir -p /usr/share/containers
install -m 644 "$RESOURCES/configs/storage.conf" /usr/share/containers/storage.conf
install -m 644 "$RESOURCES/configs/containers.conf" /usr/share/containers/containers.conf
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

# Host keys are generated on the machine, not in the image. Debian's own
# sshd-keygen.service would do it, but only on a systemd "first boot", which
# depends on /etc/machine-id being empty - too fragile a thing to hang sshd on.
# This drop-in runs the generator before sshd's own config test, every start, and
# ssh-keygen -A only creates what is missing.
mkdir -p /etc/systemd/system/ssh.service.d
install -m 644 "$RESOURCES/configs/ssh-hostkeys.conf" /etc/systemd/system/ssh.service.d/10-hostkeys.conf

# Disable systemd-ssh-generator (Debian 13 creates vsock/unix sockets, we need TCP)
mkdir -p /etc/systemd/system-generators
ln -sf /dev/null /etc/systemd/system-generators/systemd-ssh-generator
# No host keys are generated here on purpose. The build has no use for them -
# virt-customize works through libguestfs, not ssh - and a key baked into the
# image would be shared by every machine deployed from it. They are created on
# the machine itself, see the ssh.service drop-in below.
systemctl enable ssh.service
echo "✓ SSH configuration installed"

# User delegation for rootless containers
mkdir -p /etc/systemd/system/user@.service.d/
install -m 644 "$RESOURCES/configs/delegate.conf" /etc/systemd/system/user@.service.d/delegate.conf
echo "✓ User delegation configured"

# Docker storage compatibility symlink
# The image ships pure podman - no Docker Engine. The Docker compatible surface is
# podman's own API socket, which podman's Ignition config exposes as
# /run/docker.sock -> podman.sock. This symlink only points tooling that probes for
# the classic Docker storage directory at podman's storage.
ln -sf /var/lib/containers/storage /var/lib/docker
echo "✓ Docker storage compatibility symlink created"

# Enable podman.socket for root (rootful mode support)
systemctl enable podman.socket
echo "✓ Podman rootful socket enabled"

# btrfs root filesystem post-processing
if [ "$(stat -f -c %T /)" = "btrfs" ]; then
    echo ""
    echo "=== btrfs root filesystem ==="

    # btrfs-convert keeps the original ext4 image in the ext2_saved subvolume so
    # the conversion can be rolled back. The image is verified at build time, so
    # drop it - it only pins stale metadata in the shipped image.
    if [ -d /ext2_saved ]; then
        if btrfs subvolume delete /ext2_saved; then
            echo "✓ ext2_saved rollback subvolume removed"
        else
            echo "WARNING: could not remove /ext2_saved"
        fi
    fi

    # btrfs-progs was installed above; make sure the initramfs can mount a btrfs root
    update-initramfs -u -k all
    echo "✓ initramfs regenerated with btrfs support"
fi

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
echo "=== Preparing the image for cloning ==="
# Anything that identifies a machine has to be created by the machine, not by the
# build - otherwise every deployment from this image shares it. This runs last so
# nothing installed above can put them back.
rm -f /etc/ssh/ssh_host_*
echo "✓ SSH host keys removed (generated on first start)"

if [ -f /etc/machine-id ]; then
    : > /etc/machine-id
    echo "✓ machine-id cleared (generated on first boot)"
fi
rm -f /var/lib/dbus/machine-id
rm -f /var/lib/systemd/random-seed

echo ""
echo "========================================"
echo "=== Installation complete ==="
echo "========================================"
