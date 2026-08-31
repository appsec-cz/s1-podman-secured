#!/bin/bash
#
# One line saying whether this machine is still healthy, written where the host
# can read it without the machine's cooperation.
#
# A vsock endpoint was the obvious design and is not possible: podman gives the
# VM exactly one vsock device, port 1025, and the unix socket behind it exists
# only while "podman machine start" waits for the ready signal - afterwards there
# is nothing on the host to connect to, and vfkit's arguments are podman's to
# choose, not ours.
#
# The serial console is the channel that survives what this is for. vfkit is
# already capturing it to a file on the host, and it keeps working when ssh, the
# network and podman itself are gone. Note that /dev/console is tty0 here and is
# NOT that port, so writing to it reaches nobody - it has to be /dev/hvc0.
#
# Read it on the Mac with:
#   tail -f "$TMPDIR/podman/<machine>.log"

set -u

MACHINE_USER="${MACHINE_USER:-core}"
CONSOLE="${HEALTH_CONSOLE:-/dev/hvc0}"
STATE="/run/podman-machine-health.last"
# A line every beat would grow the host's log forever, so an unchanged machine
# only says so occasionally.
HEARTBEAT_SECONDS="${HEALTH_HEARTBEAT_SECONDS:-1800}"

field() { printf '%s=%s ' "$1" "$2"; }

collect() {
    local faults=0 out=""

    local failed
    failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | wc -l | tr -d ' ')
    if [ "${failed:-0}" -eq 0 ]; then
        out+=$(field units ok)
    else
        out+=$(field units "${failed}failed")
        faults=$((faults + 1))
    fi

    # The runtime, not just the daemon: a podman that cannot list containers is
    # as broken as one that is not running.
    local containers
    if containers=$(runuser -u "$MACHINE_USER" -- podman ps -q 2>/dev/null | wc -l | tr -d ' '); then
        out+=$(field podman "ok/${containers}running")
    else
        out+=$(field podman unresponsive)
        faults=$((faults + 1))
    fi

    local driver
    driver=$(runuser -u "$MACHINE_USER" -- podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null)
    case "$driver" in
        btrfs) out+=$(field storage btrfs) ;;
        "")    out+=$(field storage unknown); faults=$((faults + 1)) ;;
        *)     out+=$(field storage "$driver"); faults=$((faults + 1)) ;;
    esac

    local addr
    addr=$(ip -brief -4 addr show scope global 2>/dev/null | awk '{print $3; exit}')
    if [ -n "$addr" ]; then
        out+=$(field net "${addr%%/*}")
    else
        out+=$(field net none)
        faults=$((faults + 1))
    fi

    # Blind here means podman logs is silently empty, which is how kind fails.
    local uid jgid mgr_pid
    uid=$(id -u "$MACHINE_USER" 2>/dev/null)
    jgid=$(getent group systemd-journal 2>/dev/null | cut -d: -f3)
    mgr_pid=$(systemctl show -p MainPID --value "user@${uid}.service" 2>/dev/null)
    if [ -n "$jgid" ] && [ -n "$mgr_pid" ] && [ "$mgr_pid" != "0" ] && [ -r "/proc/$mgr_pid/status" ]; then
        if awk '/^Groups:/ {$1=""; print}' "/proc/$mgr_pid/status" 2>/dev/null | tr ' ' '\n' | grep -qx "$jgid"; then
            out+=$(field journal ok)
        else
            out+=$(field journal blind)
            faults=$((faults + 1))
        fi
    else
        out+=$(field journal unknown)
    fi

    out+=$(field up "$(cut -d. -f1 /proc/uptime 2>/dev/null)s")

    if [ "$faults" -eq 0 ]; then
        printf 'podman-machine-health: ok %s' "$out"
    else
        printf 'podman-machine-health: FAULT(%d) %s' "$faults" "$out"
    fi
}

line=$(collect)

# "up=" changes every beat, so compare without it or nothing ever looks the same.
signature=$(printf '%s' "$line" | sed 's/ up=[0-9]*s//')
last_signature=""
last_written=0
if [ -r "$STATE" ]; then
    last_signature=$(sed -n '1p' "$STATE" 2>/dev/null)
    last_written=$(sed -n '2p' "$STATE" 2>/dev/null)
fi
now=$(date +%s 2>/dev/null || echo 0)

if [ "${1:-}" = "--stdout" ]; then
    printf '%s\n' "$line"
    exit 0
fi

if [ "$signature" != "$last_signature" ] ||
   [ $((now - ${last_written:-0})) -ge "$HEARTBEAT_SECONDS" ]; then
    if [ -w "$CONSOLE" ]; then
        printf '%s\n' "$line" > "$CONSOLE" 2>/dev/null
    fi
    logger -t podman-machine-health "$line"
    printf '%s\n%s\n' "$signature" "$now" > "$STATE" 2>/dev/null
fi
