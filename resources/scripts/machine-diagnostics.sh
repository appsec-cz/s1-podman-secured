#!/bin/bash
#
# A snapshot of the things that have actually gone wrong in this machine.
#
# Every check here corresponds to a failure that shipped once and cost hours,
# because each of them is silent: the machine boots, podman answers, and only
# some later operation behaves strangely. A generic "dump everything" would bury
# them, so this deliberately asks narrow questions with known-good answers.
#
# Runs at the end of boot, after the ready signal, so it never delays
# "podman machine start". Safe to run by hand at any time:
#
#   podman machine ssh <machine> 'sudo podman-machine-diagnostics'

set -u

MACHINE_USER="${MACHINE_USER:-core}"

ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAULT %s\n' "$*"; }
info() { printf '  ---   %s\n' "$*"; }
section() { printf '\n%s\n' "$*"; }

printf 'podman machine diagnostics - %s\n' "$(date -Is 2>/dev/null)"
printf 'boot %s, up %s\n' \
    "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" \
    "$(cut -d. -f1 /proc/uptime 2>/dev/null)s"

# ---------------------------------------------------------------------------
section "identity and kernel"
info "kernel:  $(uname -r 2>/dev/null)"
info "podman:  $(runuser -u "$MACHINE_USER" -- podman --version 2>/dev/null)"
info "host:    $(hostname 2>/dev/null)"

# Shipping a machine-id in the image gives every deployment the same one, which
# breaks the journal and anything keyed on it.
if [ -s /etc/machine-id ]; then
    ok "machine-id present"
else
    bad "machine-id is empty - the journal will not work"
fi

# ---------------------------------------------------------------------------
section "units"
failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
if [ -n "${failed// /}" ]; then
    bad "failed units: $failed"
else
    ok "no failed units"
fi

for unit in ignition-provider.service post-ignition-setup.service \
            podman-machine-ready.service rosetta-activation.service ssh.service; do
    state=$(systemctl show -p ActiveState --value "$unit" 2>/dev/null)
    result=$(systemctl show -p Result --value "$unit" 2>/dev/null)
    cond=$(systemctl show -p ConditionResult --value "$unit" 2>/dev/null)
    if [ "$state" = "failed" ] || { [ -n "$result" ] && [ "$result" != "success" ]; }; then
        bad "$unit: $state ($result)"
    elif [ "$cond" = "no" ]; then
        # Normal on every boot after the first: ignition-provider is guarded by
        # its completion marker. Saying "inactive" invites a wild goose chase.
        info "$unit: skipped, its condition did not apply"
    else
        info "$unit: ${state:-unknown}"
    fi
done

# ---------------------------------------------------------------------------
# The failure this exists for: post-ignition-setup adds the machine user to
# systemd-journal, but logind may already have started the user manager for the
# lingering user, and a process keeps the supplementary groups it started with.
# The rootless podman service inside that manager then reads nothing from the
# journal, "podman logs" is silently empty over the connection, and kind dies
# waiting for "Reached target Multi-User System".
section "journal access for rootless podman"
uid=$(id -u "$MACHINE_USER" 2>/dev/null)
jgid=$(getent group systemd-journal 2>/dev/null | cut -d: -f3)

if [ -z "$uid" ] || [ -z "$jgid" ]; then
    bad "no $MACHINE_USER user or no systemd-journal group"
elif id -nG "$MACHINE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx systemd-journal; then
    ok "$MACHINE_USER is in systemd-journal (gid $jgid)"

    # A fresh login always has the group, so asking the user proves nothing. The
    # long-lived manager is what podman inherits from.
    mgr_pid=$(systemctl show -p MainPID --value "user@${uid}.service" 2>/dev/null)
    if [ -n "$mgr_pid" ] && [ "$mgr_pid" != "0" ] && [ -r "/proc/$mgr_pid/status" ]; then
        groups=$(awk '/^Groups:/ {$1=""; print}' "/proc/$mgr_pid/status" 2>/dev/null)
        if printf '%s' "$groups" | tr ' ' '\n' | grep -qx "$jgid"; then
            ok "user@${uid}.service has it too (groups:$groups)"
        else
            bad "user@${uid}.service started without it (groups:$groups)"
            bad "podman logs will be empty over the connection - restart the machine"
        fi
    else
        info "user@${uid}.service is not running, nothing has inherited yet"
    fi
else
    bad "$MACHINE_USER is not in systemd-journal - podman logs will be empty"
fi

# ---------------------------------------------------------------------------
# Podman 6 bind mounts the host's ~/.config/containers over /etc/containers,
# which hid storage.conf (driver fell back to overlay), containers.conf,
# policy.json (nothing could be pulled) and the podman-machine marker (no
# published port was ever forwarded).
section "/etc/containers"
mnt=$(findmnt -no SOURCE,FSTYPE /etc/containers 2>/dev/null)
if [ -n "$mnt" ]; then
    bad "shadowed by a mount: $mnt"
else
    ok "not shadowed by a host mount"
fi
for f in podman-machine policy.json storage.conf containers.conf; do
    if [ -e "/etc/containers/$f" ]; then
        ok "/etc/containers/$f present"
    else
        bad "/etc/containers/$f missing"
    fi
done

# ---------------------------------------------------------------------------
# Without the marker podman does not know it runs in a machine and never asks
# gvproxy to forward a port, so "podman run -p" works inside and is unreachable
# from macOS.
section "storage and port forwarding"
driver=$(runuser -u "$MACHINE_USER" -- podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null)
root=$(runuser -u "$MACHINE_USER" -- podman info --format '{{.Store.GraphRoot}}' 2>/dev/null)
case "$driver" in
    btrfs) ok "storage driver is btrfs ($root)" ;;
    "")    bad "podman could not report a storage driver" ;;
    *)     bad "storage driver is $driver, expected btrfs ($root)" ;;
esac

fwd=$(curl -s --max-time 3 http://192.168.127.1/services/forwarder/all 2>/dev/null)
if [ -n "$fwd" ]; then
    ok "gvproxy answers, forwarding $(printf '%s' "$fwd" | grep -o 'local' | wc -l | tr -d ' ') entries"
else
    info "gvproxy did not answer on 192.168.127.1 (no forwards yet is normal)"
fi

# ---------------------------------------------------------------------------
section "network"
addrs=$(ip -brief addr show scope global 2>/dev/null | awk '{printf "%s=%s ", $1, $3}')
if [ -n "$addrs" ]; then
    ok "addresses: $addrs"
else
    bad "no global address on any interface"
fi
route=$(ip route show default 2>/dev/null | head -1)
if [ -n "$route" ]; then
    ok "default route: $route"
else
    bad "no default route"
fi

# ---------------------------------------------------------------------------
# Rosetta silently falling back to qemu makes every x86_64 container slow, with
# nothing in the logs to say so.
section "x86_64 translation"
if [ -d /proc/sys/fs/binfmt_misc ]; then
    handler=$(grep -l . /proc/sys/fs/binfmt_misc/rosetta 2>/dev/null)
    if [ -n "$handler" ]; then
        ok "rosetta is the registered handler"
    elif [ -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]; then
        info "rosetta not registered, qemu-x86_64 is handling it (slower)"
    else
        bad "no x86_64 handler registered at all"
    fi
else
    bad "binfmt_misc is not mounted"
fi

# ---------------------------------------------------------------------------
# podman machine start blocks on this signal; a machine that boots fine and
# never signals looks like a hang with no explanation.
section "ready signal"
if [ -r /run/podman-machine-ready-signal ]; then
    result=$(cat /run/podman-machine-ready-signal 2>/dev/null)
    case "$result" in
        sent*) ok "vsock ready signal $result" ;;
        *)     bad "vsock ready signal $result" ;;
    esac
else
    info "no ready signal recorded yet"
fi

printf '\n'
