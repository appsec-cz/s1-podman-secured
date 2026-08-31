#!/bin/bash
# Post-Ignition setup for Podman machine
#
# This script runs AFTER ignition-provider.py has applied the Ignition config.
# It only configures things that Ignition does NOT handle (sudoers, SSH forwarding).
# It respects values already set by Ignition and does not overwrite them.
#
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

# Set up sudoers (Ignition doesn't do this)
if [ ! -f "/etc/sudoers.d/$USERNAME" ]; then
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME
    chmod 0440 /etc/sudoers.d/$USERNAME
    logger "post-ignition-setup: Sudoers configured"
else
    logger "post-ignition-setup: Sudoers already configured (skipping)"
fi

# Check subuid/subgid - only set if NOT already configured by Ignition
# Ignition sets these from /etc/subuid and /etc/subgid files in the config
if grep -q "^$USERNAME:" /etc/subuid 2>/dev/null; then
    CURRENT_SUBUID=$(grep "^$USERNAME:" /etc/subuid)
    logger "post-ignition-setup: subuid already set by Ignition: $CURRENT_SUBUID (keeping)"
else
    # Fallback: set default if Ignition didn't configure it
    echo "$USERNAME:100000:1000000" >> /etc/subuid
    logger "post-ignition-setup: subuid set (fallback): $USERNAME:100000:1000000"
fi

if grep -q "^$USERNAME:" /etc/subgid 2>/dev/null; then
    CURRENT_SUBGID=$(grep "^$USERNAME:" /etc/subgid)
    logger "post-ignition-setup: subgid already set by Ignition: $CURRENT_SUBGID (keeping)"
else
    # Fallback: set default if Ignition didn't configure it
    echo "$USERNAME:100000:1000000" >> /etc/subgid
    logger "post-ignition-setup: subgid set (fallback): $USERNAME:100000:1000000"
fi

# Enable SSH config with StreamLocal forwarding (Ignition doesn't do this)
if [ ! -f /etc/ssh/sshd_config.d/streamlocal.conf ]; then
    cat > /etc/ssh/sshd_config.d/streamlocal.conf << 'SSHEOF'
# Allow SSH socket forwarding for Podman Desktop
AllowStreamLocalForwarding yes
AllowTcpForwarding yes
StreamLocalBindUnlink yes
SSHEOF
    logger "post-ignition-setup: SSH StreamLocal forwarding enabled"
    # --no-block or this deadlocks: the unit is ordered before user sessions and
    # systemd will not run an ssh job while this script is still running.
    systemctl reload ssh.service --no-block 2>/dev/null || true
else
    logger "post-ignition-setup: SSH StreamLocal already configured (skipping)"
fi

# Note: The following are handled by Ignition and we don't touch them:
# - /var/lib/systemd/linger/$USERNAME (from storage.files)
# - $USER_HOME/.config/systemd/user/sockets.target.wants/podman.socket (from storage.links)
# - $USER_HOME/.config/containers/containers.conf (from storage.files)
# - /etc/tmpfiles.d/podman-docker.conf (from storage.files)

# Journal access for the user
# podman's default log driver is journald and rootless podman reads container logs
# back from the journal. Without membership in systemd-journal the read returns
# nothing, so "podman logs" is silently empty - which breaks anything that waits for
# a log line, kind most notably ("could not find a log line that matches
# Reached target Multi-User System").
if getent group systemd-journal > /dev/null 2>&1; then
    if ! id -nG "$USERNAME" | tr ' ' '\n' | grep -qx systemd-journal; then
        usermod -aG systemd-journal "$USERNAME"
        logger "post-ignition-setup: Added $USERNAME to systemd-journal (podman logs)"
        # A process keeps the supplementary groups it started with, so a user
        # manager logind has already brought up - and the rootless podman API
        # service inside it - would go on reading nothing from the journal. The
        # unit ordering should prevent that; restart it if it happened anyway.
        if systemctl is-active --quiet "user@$USER_UID.service"; then
            # Same trap as the ssh reload above: waiting on a systemd job from
            # inside a unit that job is ordered after never returns.
            systemctl restart "user@$USER_UID.service" --no-block || true
            logger "post-ignition-setup: Restarted user@$USER_UID.service for the new group"
        fi
    else
        logger "post-ignition-setup: $USERNAME already in systemd-journal"
    fi
fi

# Container image trust policy
# Podman 6 mounts the host's ~/.config/containers over /etc/containers inside the
# VM, which hides /etc/containers/policy.json. Without a policy file podman cannot
# pull any image ("no policy.json file found"), so put a copy in the per-user
# locations, which the mount cannot shadow.
if [ ! -f /etc/containers/policy.json ]; then
    for POLICY_DIR in "$USER_HOME/.config/containers" /root/.config/containers; do
        mkdir -p "$POLICY_DIR"
        if [ ! -f "$POLICY_DIR/policy.json" ]; then
            cat > "$POLICY_DIR/policy.json" << 'POLICYEOF'
{
    "default": [{"type": "insecureAcceptAnything"}],
    "transports": {
        "docker-daemon": {"": [{"type": "insecureAcceptAnything"}]}
    }
}
POLICYEOF
        fi
    done
    chown -R "$USER_UID:$USER_GID" "$USER_HOME/.config/containers"
    logger "post-ignition-setup: policy.json fallback installed (/etc/containers is shadowed by host mount)"
else
    logger "post-ignition-setup: /etc/containers/policy.json present (skipping fallback)"
fi

# Apply tmpfiles configuration (in case Ignition created new tmpfiles)
systemd-tmpfiles --create 2>/dev/null || true

logger "post-ignition-setup: Completed successfully"
