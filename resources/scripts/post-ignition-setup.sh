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
