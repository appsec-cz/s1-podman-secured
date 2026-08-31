#!/bin/bash
#
# Podman Machine Deployment Script
#
# Standalone script for deploying Podman machine with custom image.
# Can be used independently - just needs the image file in current directory.
#
# Usage:
#   ./deploy.sh [--token <s1-token>] [--cpus N] [--memory N] [--disk-size N]
#

set -e

# Set provider early - needed for all podman machine commands
export CONTAINERS_MACHINE_PROVIDER=applehv

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Fixed machine name. The override exists so the test suite can drive this
# against its own throwaway machine instead of the one someone works on.
MACHINE_NAME="${PODMAN_MACHINE_NAME:-podman-machine-default}"

# Defaults
S1_TOKEN=""
CPUS="4"
MEMORY="4096"
DISK_SIZE="100"
IMAGE_PATH=""
INTERACTIVE=false
MODE="deploy"
PRESERVE=false
KEEP_BACKUP=false
BACKUP_DIR=""
BACKUP_ROOT="$HOME/.local/share/containers/podman/machine/backups"
BACKUP_SITE_KEY=""
RESTORE_STATUS=0

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Create a secured Podman machine with optional SentinelOne agent.
Machine name is always 'podman-machine-default'.

Looks for files in current directory:
  - podman-debian*.raw.zst  (required)
  - SentinelAgent*.deb      (optional)

Options:
  --token, -t TOKEN    SentinelOne registration token (prompts if not provided)
  --cpus N             Number of CPUs (default: 4)
  --memory N           Memory in MB (default: 4096)
  --disk-size N        Disk size in GB (default: 100)
  --image PATH         Path to image (default: auto-detect in current dir)
  --preserve           Back up images, volumes and containers before replacing
                       the machine, and restore them into the new one
  --keep-backup        Keep the backup directory after a verified restore
  --backup-only        Only back up the current machine's data, then exit
  --restore DIR        Only restore a backup into the running machine, then exit
  --help, -h           Show this help

Examples:
  $0
  $0 --token eyJ... --cpus 8 --memory 8192
  $0 --preserve --token eyJ...
  $0 --backup-only
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h) usage; exit 0 ;;
            --token|-t) S1_TOKEN="$2"; shift 2 ;;
            --cpus) CPUS="$2"; shift 2 ;;
            --memory) MEMORY="$2"; shift 2 ;;
            --disk-size) DISK_SIZE="$2"; shift 2 ;;
            --image) IMAGE_PATH="$2"; shift 2 ;;
            --preserve) PRESERVE=true; shift ;;
            --keep-backup) KEEP_BACKUP=true; shift ;;
            --backup-only) MODE="backup"; shift ;;
            --restore) MODE="restore"; BACKUP_DIR="$2"; shift 2 ;;
            *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
        esac
    done
}

check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"

    command -v podman &>/dev/null || { echo -e "${RED}Error: podman not found${NC}"; exit 1; }

    # Find image file - explicit path takes precedence
    if [ -n "$IMAGE_PATH" ]; then
        if [ ! -f "$IMAGE_PATH" ]; then
            echo -e "${RED}Error: Image not found: $IMAGE_PATH${NC}"
            exit 1
        fi
    else
        # Auto-detect in current directory
        IMAGE_PATH=$(find . -maxdepth 1 -name "podman-debian*.raw.zst" -type f 2>/dev/null | head -1)
        if [ -z "$IMAGE_PATH" ]; then
            echo -e "${RED}Error: No podman-debian*.raw.zst found in current directory${NC}"
            echo ""
            echo "Either:"
            echo "  1. Copy the image to the current directory"
            echo "  2. Use --image PATH to specify the image location"
            exit 1
        fi
    fi

    # Find SentinelOne package (optional)
    S1_PACKAGE=$(find . -maxdepth 1 -name "SentinelAgent*.deb" -type f 2>/dev/null | head -1)

    echo -e "${GREEN}OK${NC}"
    echo "  Image: $(basename "$IMAGE_PATH")"
    if [ -n "$S1_PACKAGE" ]; then
        echo "  SentinelOne: $(basename "$S1_PACKAGE")"
    else
        echo "  SentinelOne: not found (will skip installation)"
    fi
}

# Rosetta translates x86_64 binaries natively on Apple Silicon; without it the
# image falls back to qemu-user emulation, which works but is far slower.
#
# This has to go into the real containers.conf, not a temporary one passed to
# init: podman re-derives the setting from containers.conf on every machine
# start and rewrites the machine config, so a value that is only present at init
# time is silently turned off again by the next plain "podman machine start" -
# including the ones Podman Desktop issues.
enable_rosetta() {
    if [ "$(uname -m)" != "arm64" ]; then
        echo -e "${YELLOW}Not Apple Silicon - x86_64 containers will use QEMU emulation${NC}"
        return 0
    fi

    local conf="$HOME/.config/containers/containers.conf"
    mkdir -p "$(dirname "$conf")"
    [ -f "$conf" ] || : > "$conf"

    if grep -qE '^[[:space:]]*rosetta[[:space:]]*=[[:space:]]*true' "$conf"; then
        echo -e "${BLUE}Rosetta already enabled in $conf${NC}"
        return 0
    fi

    cp "$conf" "${conf}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    if grep -qE '^[[:space:]]*rosetta[[:space:]]*=' "$conf"; then
        sed -i '' -E 's/^[[:space:]]*rosetta[[:space:]]*=.*/rosetta = true/' "$conf"
    elif grep -qE '^\[machine\]' "$conf"; then
        sed -i '' -E 's/^\[machine\]/[machine]\'$'\n''rosetta = true/' "$conf"
    else
        printf '\n[machine]\nrosetta = true\n' >> "$conf"
    fi

    echo -e "${BLUE}Rosetta enabled in $conf (a backup of the previous file is next to it)${NC}"
}

# ---------------------------------------------------------------------------
# Data migration across a machine replacement
#
# "podman machine rm" takes the disk with it, and the rootless store lives inside
# that disk - every image, volume and container. The store cannot just be copied
# out: the storage driver is btrfs and each image layer is its own subvolume, so
# a tar of the graph root comes back as plain directories that the driver can no
# longer snapshot. Everything here therefore goes through podman's own export
# formats, which survive a version change and do not care what filesystem is
# underneath.
#
# The guest writes straight into the backup directory. $HOME is under /Users,
# which the machine mounts over virtiofs at the same absolute path, so several
# gigabytes never have to travel through the ssh connection.
# ---------------------------------------------------------------------------

# Feed a script to the machine on stdin. Callers pass VAR=value prelude lines so
# paths do not have to survive two rounds of shell quoting.
guest_script() {
    local script="$1"; shift
    local kv
    {
        for kv in "$@"; do printf '%s\n' "$kv"; done
        printf '%s\n' "$script"
    } | podman machine ssh "$MACHINE_NAME" 'bash -s'
}

machine_is_running() {
    [ "$(podman machine inspect "$MACHINE_NAME" --format '{{.State}}' 2>/dev/null)" = "running" ]
}

require_machine_running() {
    if ! podman machine inspect "$MACHINE_NAME" &>/dev/null; then
        echo -e "${RED}Error: machine '$MACHINE_NAME' does not exist${NC}"
        exit 1
    fi
    if ! machine_is_running; then
        echo -e "${BLUE}Starting machine '$MACHINE_NAME'...${NC}"
        podman machine start "$MACHINE_NAME" >/dev/null
        local i
        for i in $(seq 1 30); do
            podman machine ssh "$MACHINE_NAME" "echo ok" &>/dev/null && break
            sleep 2
        done
    fi
}

BACKUP_GUEST_SCRIPT='
set -u
mkdir -p "$DIR/volumes" "$DIR/containers"

# kind nodes are deliberately left out. A node is a running kubelet with etcd
# state behind it, and replaying its definition does not give back a working
# cluster - kind has to build those again itself.
podman ps -a --format "{{.Names}}" | sort > "$DIR/all.txt"
podman ps -a --filter label=io.x-k8s.kind.cluster --format "{{.Names}}" | sort > "$DIR/skipped.txt"
comm -23 "$DIR/all.txt" "$DIR/skipped.txt" > "$DIR/carried.txt"

# Written before anything is filtered out, so a container this cannot express
# still has its full state recorded somewhere. Pointing someone at this file and
# leaving it empty is worse than not offering it.
if [ -s "$DIR/carried.txt" ]; then
    xargs -r podman container inspect < "$DIR/carried.txt" > "$DIR/containers.json" 2>/dev/null || true
fi
podman pod ls --format "{{.Name}}" | sort > "$DIR/pods.txt"
if [ -s "$DIR/pods.txt" ]; then
    xargs -r podman pod inspect < "$DIR/pods.txt" > "$DIR/pods.json" 2>/dev/null || true
fi

# A container that belongs to a pod cannot be generated on its own - podman
# refuses with "use generate on the pod itself" - and an infra container never
# can. So pods are taken whole and only containers outside any pod individually.
# Generating several containers into one file is still avoided: that would put
# unrelated containers in a pod and hand them a shared network namespace.
podman ps -a --format "{{.Pod}}\t{{.Names}}" | awk -F"\t" "\$1 == \"\" {print \$2}" | sort > "$DIR/standalone.txt"
comm -23 "$DIR/standalone.txt" "$DIR/skipped.txt" > "$DIR/containers.txt"
podman ps -a --format "{{.PodName}}\t{{.IsInfra}}\t{{.Names}}" \
    | awk -F"\t" "\$1 != \"\" && \$2 == \"false\" {print \$1 \"\t\" \$3}" | sort > "$DIR/members.txt"

# Recorded before anything is stopped below - taken afterwards this is always
# empty, and the restore then leaves everything down.
#
# Only containers, never pod status: podman calls a pod with some of its
# containers down "Degraded", and reading that as stopped takes the running ones
# with it. Starting a container in a stopped pod brings the pod up anyway.
podman ps --format "{{.Names}}" | sort > "$DIR/running-all.txt"

# A container still writing would hand us a torn volume.
if [ -s "$DIR/pods.txt" ]; then
    xargs -r podman pod stop -t 10 < "$DIR/pods.txt" >/dev/null 2>&1 || true
fi
if [ -s "$DIR/containers.txt" ]; then
    xargs -r podman stop -t 10 < "$DIR/containers.txt" >/dev/null 2>&1 || true
fi

podman images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" | sort -u > "$DIR/images.txt"
if [ -s "$DIR/images.txt" ]; then
    xargs -r podman save --multi-image-archive -o "$DIR/images.tar" < "$DIR/images.txt" || echo "BACKUP_FAIL images"
fi

podman volume ls --format "{{.Name}}" | sort > "$DIR/volumes.txt"
if [ -s "$DIR/volumes.txt" ]; then
    xargs -r podman volume inspect < "$DIR/volumes.txt" > "$DIR/volumes.json" || echo "BACKUP_FAIL volume-inspect"
    while read -r v; do
        podman volume export "$v" -o "$DIR/volumes/$v.tar" || echo "BACKUP_FAIL volume $v"
    done < "$DIR/volumes.txt"
fi

# Anything that cannot be generated is recorded and dropped rather than treated
# as a failure: the list is a snapshot, and a --rm container that exits between
# the listing and the export is simply gone. That must not cost the images.
: > "$DIR/ungenerated.txt"
: > "$DIR/ungenerated-pods.txt"
while read -r pod; do
    [ -n "$pod" ] || continue
    if ! podman kube generate --podman-only "$pod" > "$DIR/containers/pod-$pod.yaml" 2>/dev/null; then
        rm -f "$DIR/containers/pod-$pod.yaml"
        echo "$pod" >> "$DIR/ungenerated-pods.txt"
    fi
done < "$DIR/pods.txt"
while read -r c; do
    [ -n "$c" ] || continue
    if ! podman kube generate --podman-only "$c" > "$DIR/containers/ctr-$c.yaml" 2>/dev/null; then
        rm -f "$DIR/containers/ctr-$c.yaml"
        echo "$c" >> "$DIR/ungenerated.txt"
    fi
done < "$DIR/containers.txt"

# What the restore may promise: standalone containers that generated, plus the
# members of pods that generated. Infra containers are left out - a rebuilt pod
# gets a new one under a different name.
sort -o "$DIR/ungenerated.txt" "$DIR/ungenerated.txt"
sort -o "$DIR/ungenerated-pods.txt" "$DIR/ungenerated-pods.txt"
comm -23 "$DIR/containers.txt" "$DIR/ungenerated.txt" > "$DIR/containers.keep"
mv "$DIR/containers.keep" "$DIR/containers.txt"
comm -23 "$DIR/pods.txt" "$DIR/ungenerated-pods.txt" > "$DIR/pods.keep"
mv "$DIR/pods.keep" "$DIR/pods.txt"

cp "$DIR/containers.txt" "$DIR/expected.txt"
while read -r pod name; do
    grep -qx "$pod" "$DIR/pods.txt" 2>/dev/null && echo "$name" >> "$DIR/expected.txt"
done < "$DIR/members.txt"
sort -u -o "$DIR/expected.txt" "$DIR/expected.txt"

comm -12 "$DIR/running-all.txt" "$DIR/expected.txt" > "$DIR/running.txt"

# The stop above was ours, and taking a backup is not a reason to leave someone
# with their containers down - least of all with --backup-only, where no machine
# is being replaced at all.
if [ -s "$DIR/running.txt" ]; then
    xargs -r podman start < "$DIR/running.txt" >/dev/null 2>&1 || true
fi

podman --version > "$DIR/guest-podman-version.txt" 2>/dev/null || true
du -sk "$DIR" 2>/dev/null | cut -f1 > "$DIR/size-kb.txt"
'

backup_machine() {
    if ! podman machine inspect "$MACHINE_NAME" &>/dev/null; then
        echo -e "${YELLOW}No machine '$MACHINE_NAME' to back up - nothing to preserve${NC}"
        BACKUP_DIR=""
        return 0
    fi
    require_machine_running

    BACKUP_DIR="$BACKUP_ROOT/${MACHINE_NAME}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # The export needs roughly what the store occupies. Finding that out after
    # writing half of it is no use to anybody.
    local need_kb free_kb
    need_kb=$(podman machine ssh "$MACHINE_NAME" \
        "du -sk ~/.local/share/containers 2>/dev/null | cut -f1" 2>/dev/null | tr -d '\r')
    free_kb=$(df -k "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
    if [ -n "$need_kb" ] && [ -n "$free_kb" ] && [ "$need_kb" -gt "$free_kb" ]; then
        echo -e "${RED}Error: the store is $((need_kb / 1024)) MB and only $((free_kb / 1024)) MB is free${NC}"
        echo "  Backup directory: $BACKUP_ROOT"
        rmdir "$BACKUP_DIR" 2>/dev/null || true
        exit 1
    fi

    echo -e "${BLUE}Backing up machine data...${NC}"
    echo "  Into: $BACKUP_DIR"
    local out
    out=$(guest_script "$BACKUP_GUEST_SCRIPT" "DIR=$(printf '%q' "$BACKUP_DIR")" 2>&1 | tr -d '\r')
    if printf '%s' "$out" | grep -q "BACKUP_FAIL"; then
        echo -e "${RED}Error: the backup did not complete${NC}"
        printf '%s\n' "$out" | grep "BACKUP_FAIL" | sed 's/^/  /'
        exit 1
    fi

    write_backup_manifest
    print_backup_contents
}

write_backup_manifest() {
    local site_key
    site_key=$(podman machine ssh "$MACHINE_NAME" \
        "sudo /opt/sentinelone/bin/sentinelctl management status 2>/dev/null | awk '/^Site-Key/ {print \$2}'" \
        2>/dev/null | tr -d '\r')
    BACKUP_SITE_KEY="$site_key"

    # The site key identifies which endpoint to decommission in the console. The
    # registration token is deliberately not stored - it is a secret, and the new
    # machine takes it from --token instead.
    python3 - "$BACKUP_DIR" "$MACHINE_NAME" "$site_key" <<'PY'
import json, os, subprocess, sys, time

d, machine, site_key = sys.argv[1], sys.argv[2], sys.argv[3]


def read(name):
    try:
        with open(os.path.join(d, name)) as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


def guest_version():
    try:
        with open(os.path.join(d, "guest-podman-version.txt")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


manifest = {
    "machine": machine,
    "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "host_podman": subprocess.run(
        ["podman", "--version"], capture_output=True, text=True
    ).stdout.strip(),
    "guest_podman": guest_version(),
    "images": read("images.txt"),
    "volumes": read("volumes.txt"),
    "containers": read("expected.txt"),
    "pods": read("pods.txt"),
    "running": read("running.txt"),
    "skipped": read("skipped.txt"),
    "ungenerated": read("ungenerated.txt") + ["pod " + p for p in read("ungenerated-pods.txt")],
    "sentinelone_site_key": site_key,
}
with open(os.path.join(d, "manifest.json"), "w") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY
}

print_backup_contents() {
    local images volumes containers pods skipped size
    images=$(wc -l < "$BACKUP_DIR/images.txt" 2>/dev/null | tr -d ' ')
    volumes=$(wc -l < "$BACKUP_DIR/volumes.txt" 2>/dev/null | tr -d ' ')
    containers=$(wc -l < "$BACKUP_DIR/expected.txt" 2>/dev/null | tr -d ' ')
    pods=$(wc -l < "$BACKUP_DIR/pods.txt" 2>/dev/null | tr -d ' ')
    skipped=$(wc -l < "$BACKUP_DIR/skipped.txt" 2>/dev/null | tr -d ' ')
    size=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)

    echo -e "${GREEN}  Backed up: ${images:-0} images, ${volumes:-0} volumes, ${containers:-0} containers in ${pods:-0} pods (${size:-?})${NC}"
    if [ "${skipped:-0}" -gt 0 ]; then
        echo -e "${YELLOW}  Skipped ${skipped} kind node(s) - recreate those clusters with kind${NC}"
        sed 's/^/    - /' "$BACKUP_DIR/skipped.txt"
    fi
    if [ -s "$BACKUP_DIR/ungenerated.txt" ] || [ -s "$BACKUP_DIR/ungenerated-pods.txt" ]; then
        echo -e "${YELLOW}  No definition could be generated for:${NC}"
        sed 's/^/    - /' "$BACKUP_DIR/ungenerated.txt" 2>/dev/null
        sed 's/^/    - pod /' "$BACKUP_DIR/ungenerated-pods.txt" 2>/dev/null
        echo "    (their full state is in containers.json and pods.json)"
    fi
}

RESTORE_GUEST_SCRIPT='
set -u
if [ -f "$DIR/images.tar" ]; then
    podman load -i "$DIR/images.tar" >/dev/null || echo "RESTORE_FAIL load"
fi

if [ -s "$DIR/volumes-create.sh" ]; then
    bash "$DIR/volumes-create.sh" >/dev/null 2>&1 || true
fi
if [ -s "$DIR/volumes.txt" ]; then
    while read -r v; do
        [ -f "$DIR/volumes/$v.tar" ] || continue
        podman volume import "$v" "$DIR/volumes/$v.tar" || echo "RESTORE_FAIL volume $v"
    done < "$DIR/volumes.txt"
fi

# kube play always builds a pod, but --no-pod-prefix keeps the container itself
# under its own name instead of <pod>-<name>. Every script and habit built around
# those names has to still work on the other side of an update.
for f in "$DIR"/containers/*.yaml; do
    [ -e "$f" ] || continue
    podman kube play --no-pod-prefix "$f" >/dev/null 2>&1 ||
        podman kube play "$f" >/dev/null 2>&1 ||
        echo "RESTORE_FAIL play $(basename "$f" .yaml)"
done

if [ -s "$DIR/expected.txt" ]; then
    # Fallback for a podman without --no-pod-prefix, which names it <name>-pod-<name>.
    while read -r c; do
        if podman container exists "${c}-pod-${c}" && ! podman container exists "$c"; then
            podman rename "${c}-pod-${c}" "$c" >/dev/null 2>&1 || echo "RESTORE_FAIL rename $c"
        fi
    done < "$DIR/expected.txt"

    # kube play starts everything it creates; stop again what was not running.
    while read -r c; do
        grep -qx "$c" "$DIR/running.txt" 2>/dev/null || podman stop -t 5 "$c" >/dev/null 2>&1 || true
    done < "$DIR/expected.txt"
fi
'

VERIFY_GUEST_SCRIPT='
set -u
fail=0
now=$(mktemp -d)

podman images --format "{{.Repository}}:{{.Tag}}" | sort -u > "$now/images"
podman volume ls --format "{{.Name}}" | sort > "$now/volumes"
podman ps -a --format "{{.Names}}" | sort > "$now/containers"
podman ps --format "{{.Names}}" | sort > "$now/running"
podman pod ls --format "{{.Name}}" | sort > "$now/pods"

while read -r i; do
    grep -qx "$i" "$now/images" || { echo "MISSING image $i"; fail=1; }
done < "$DIR/images.txt"

while read -r v; do
    grep -qx "$v" "$now/volumes" || { echo "MISSING volume $v"; fail=1; }
done < "$DIR/volumes.txt"

# expected.txt is standalone containers plus the members of pods that were
# captured - never infra, which comes back under a new name.
while read -r c; do
    grep -qx "$c" "$now/containers" || { echo "MISSING container $c"; fail=1; }
done < "$DIR/expected.txt"

while read -r pod; do
    grep -qx "$pod" "$now/pods" || { echo "MISSING pod $pod"; fail=1; }
done < "$DIR/pods.txt"

while read -r c; do
    grep -qx "$c" "$now/running" || { echo "MISSING running $c"; fail=1; }
done < "$DIR/running.txt"

rm -rf "$now"
[ "$fail" -eq 0 ] && echo VERIFY_OK || echo VERIFY_FAILED
'

# Volumes have to exist before they can be imported, and they have to come back
# with the driver, labels and options they had - an imported volume with the
# wrong driver is not the volume that was backed up.
write_volume_create_script() {
    local dir="$1"
    [ -s "$dir/volumes.json" ] || return 0
    python3 - "$dir" <<'PY'
import json, os, shlex, sys

d = sys.argv[1]
with open(os.path.join(d, "volumes.json")) as fh:
    volumes = json.load(fh)

lines = []
for v in volumes:
    cmd = ["podman", "volume", "create"]
    driver = v.get("Driver")
    if driver and driver != "local":
        cmd += ["--driver", driver]
    for key, value in sorted((v.get("Labels") or {}).items()):
        cmd += ["--label", "%s=%s" % (key, value)]
    for key, value in sorted((v.get("Options") or {}).items()):
        cmd += ["--opt", "%s=%s" % (key, value)]
    cmd.append(v["Name"])
    lines.append(" ".join(shlex.quote(part) for part in cmd))

with open(os.path.join(d, "volumes-create.sh"), "w") as fh:
    fh.write("\n".join(lines) + "\n" if lines else "")
PY
}

restore_machine() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Error: no backup at $dir${NC}"
        exit 1
    fi
    require_machine_running

    # An archive written by a newer podman may simply not load into an older one.
    local was now
    was=$(cat "$dir/guest-podman-version.txt" 2>/dev/null | tr -d '\r')
    now=$(podman machine ssh "$MACHINE_NAME" "podman --version" 2>/dev/null | tr -d '\r')
    if [ -n "$was" ] && [ -n "$now" ] && [ "$was" != "$now" ]; then
        echo -e "${YELLOW}  Backup came from '$was', restoring into '$now'${NC}"
    fi

    echo -e "${BLUE}Restoring machine data...${NC}"
    echo "  From: $dir"
    write_volume_create_script "$dir"

    local out
    out=$(guest_script "$RESTORE_GUEST_SCRIPT" "DIR=$(printf '%q' "$dir")" 2>&1 | tr -d '\r')
    if printf '%s' "$out" | grep -q "RESTORE_FAIL"; then
        echo -e "${YELLOW}  Some items did not restore:${NC}"
        printf '%s\n' "$out" | grep "RESTORE_FAIL" | sed 's/^/    /'
    fi

    echo -e "${BLUE}Verifying...${NC}"
    local report
    report=$(guest_script "$VERIFY_GUEST_SCRIPT" "DIR=$(printf '%q' "$dir")" 2>&1 | tr -d '\r')
    if printf '%s' "$report" | grep -q "VERIFY_OK"; then
        echo -e "${GREEN}  Everything in the backup is back${NC}"
        discard_backup "$dir"
        return 0
    fi

    echo -e "${RED}  The restore is incomplete:${NC}"
    printf '%s\n' "$report" | grep "^MISSING" | sed 's/^/    /'
    echo -e "${YELLOW}  Backup kept at $dir${NC}"
    echo "  Container definitions that kube generate could not express are in"
    echo "  $dir/containers.json"
    return 1
}

# Only ever reached with a verified restore behind it: the data now exists twice
# and the copy in the machine is the one that gets used.
discard_backup() {
    local dir="$1"
    if [ "$KEEP_BACKUP" = "true" ]; then
        echo -e "${BLUE}  Backup kept at $dir${NC}"
        return 0
    fi
    case "$dir" in
        "$BACKUP_ROOT"/*) ;;
        *)
            echo -e "${YELLOW}  Backup at $dir is outside $BACKUP_ROOT - leaving it alone${NC}"
            return 0
            ;;
    esac
    rm -rf "$dir"
    echo -e "${GREEN}  Backup removed${NC}"
}

create_machine() {
    # Check if machine already exists (using inspect for reliable detection)
    if podman machine inspect "$MACHINE_NAME" &>/dev/null; then
        echo ""
        echo -e "${YELLOW}Machine '$MACHINE_NAME' already exists.${NC}"

        # Show current machine info
        echo ""
        podman machine list 2>/dev/null | grep -E "^NAME|$MACHINE_NAME"
        echo ""

        if [ -t 0 ]; then
            # Interactive mode - ask user
            if [ "$PRESERVE" = "true" ] && [ -n "$BACKUP_DIR" ]; then
                echo -e "${GREEN}Its data is backed up in $BACKUP_DIR${NC}"
            fi
            read -p "Remove existing machine and create new one? [y/N]: " answer
            if [[ "$answer" =~ ^[Yy] ]]; then
                echo -e "${YELLOW}Removing existing machine...${NC}"
                podman machine stop "$MACHINE_NAME" 2>/dev/null || true
                podman machine rm -f "$MACHINE_NAME" 2>/dev/null || true
            else
                echo -e "${BLUE}Keeping existing machine. Exiting.${NC}"
                [ -n "$BACKUP_DIR" ] && echo "Backup left at $BACKUP_DIR"
                exit 0
            fi
        elif [ "$PRESERVE" = "true" ] && [ -n "$BACKUP_DIR" ]; then
            # --preserve is the caller saying "replace it, keep my data", and the
            # data is already out and verified by the time we get here. Jamf runs
            # have no terminal to answer a prompt.
            echo -e "${YELLOW}Removing existing machine (data backed up in $BACKUP_DIR)...${NC}"
            podman machine stop "$MACHINE_NAME" 2>/dev/null || true
            podman machine rm -f "$MACHINE_NAME" 2>/dev/null || true
        else
            # Non-interactive mode - fail with helpful message
            echo -e "${RED}Error: Machine already exists.${NC}"
            echo "Run interactively to remove, or use --preserve to replace it"
            echo "while keeping its data. To remove it by hand:"
            echo "  podman machine stop $MACHINE_NAME"
            echo "  podman machine rm -f $MACHINE_NAME"
            exit 1
        fi
    fi

    echo -e "${BLUE}Creating machine '$MACHINE_NAME'...${NC}"
    enable_rosetta
    podman machine init "$MACHINE_NAME" \
        --image "$IMAGE_PATH" \
        --cpus "$CPUS" \
        --memory "$MEMORY" \
        --disk-size "$DISK_SIZE"

    echo -e "${BLUE}Starting machine...${NC}"
    podman machine start "$MACHINE_NAME"

    echo "Waiting for SSH..."
    for i in {1..30}; do
        podman machine ssh "$MACHINE_NAME" "echo ok" &>/dev/null && break
        sleep 2
    done

    # Confirm what podman actually did with it. A silent miss here means every
    # x86_64 container falls back to qemu emulation.
    if [ "$(uname -m)" = "arm64" ]; then
        if [ "$(podman machine inspect "$MACHINE_NAME" --format '{{.Rosetta}}' 2>/dev/null)" = "true" ]; then
            echo -e "${GREEN}Rosetta is active for this machine${NC}"
        else
            echo -e "${YELLOW}WARNING: Rosetta did not take effect - x86_64 containers will use QEMU emulation${NC}"
        fi
    fi

    echo -e "${GREEN}Machine is running${NC}"
}

deploy_sentinelone() {
    # Skip if no package found
    if [ -z "$S1_PACKAGE" ]; then
        echo -e "${YELLOW}Skipping SentinelOne (no package found)${NC}"
        return
    fi

    local package_name=$(basename "$S1_PACKAGE")
    local vm_hostname="$(hostname -s)-podman"

    echo -e "${BLUE}Deploying SentinelOne...${NC}"

    # Set hostname based on Mac hostname with -podman suffix
    echo "  Setting hostname: $vm_hostname"
    podman machine ssh "$MACHINE_NAME" "sudo bash -c '
        echo \"$vm_hostname\" > /etc/hostname
        hostname \"$vm_hostname\"
    '"

    # Upload package
    echo "  Uploading package..."
    cat "$S1_PACKAGE" | podman machine ssh "$MACHINE_NAME" "cat > /tmp/$package_name"

    # Install package
    echo "  Installing SentinelOne..."
    podman machine ssh "$MACHINE_NAME" "sudo dpkg -i /tmp/$package_name 2>&1 || sudo apt-get install -f -y 2>&1" >/dev/null

    # Register if token provided
    if [ -n "$S1_TOKEN" ]; then
        echo "  Registering agent..."
        podman machine ssh "$MACHINE_NAME" "sudo /opt/sentinelone/bin/sentinelctl management token set \"$S1_TOKEN\"" >/dev/null 2>&1 || \
            echo -e "${YELLOW}  Token could not be set - register manually with sentinelctl${NC}"
    fi

    # Start it whether or not a token was given. Installing the package enables
    # the unit but does not start it, so without this the agent sits idle until
    # the machine is rebooted - and an unregistered agent still needs to be
    # running for the token to be applied later.
    podman machine ssh "$MACHINE_NAME" "sudo systemctl enable --now sentinelone" >/dev/null 2>&1 || true
    sleep 2
    if [ "$(podman machine ssh "$MACHINE_NAME" 'systemctl is-active sentinelone' 2>/dev/null | tr -d '\r')" = "active" ]; then
        echo -e "${GREEN}  Agent running${NC}"
    else
        echo -e "${YELLOW}  WARNING: the agent is installed but not running${NC}"
    fi

    # Cleanup
    podman machine ssh "$MACHINE_NAME" "rm -f /tmp/$package_name" 2>/dev/null || true

    echo -e "${GREEN}Done${NC}"
}

prompt_for_token() {
    # Skip if no S1 package or token already provided
    [ -z "$S1_PACKAGE" ] && return
    [ -n "$S1_TOKEN" ] && return

    # Check if running interactively
    if [ -t 0 ]; then
        INTERACTIVE=true
        echo ""
        echo "SentinelOne token (from console: Settings > Sites > Site Token)"
        read -p "Enter token (or Enter to skip): " S1_TOKEN
    fi
}

cleanup_old_machines() {
    # Only in interactive mode
    [ "$INTERACTIVE" != "true" ] && return

    # Get list of other machines (not the one we're creating)
    local other_machines
    other_machines=$(podman machine list --format "{{.Name}}" 2>/dev/null | grep -v "^${MACHINE_NAME}$" || true)

    [ -z "$other_machines" ] && return

    echo ""
    echo -e "${YELLOW}Existing Podman machines found:${NC}"
    echo "$other_machines" | while read -r m; do
        echo "  - $m"
    done
    echo ""
    read -p "Remove existing machines? [y/N]: " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        echo "$other_machines" | while read -r m; do
            echo -e "  Removing ${YELLOW}$m${NC}..."
            podman machine stop "$m" 2>/dev/null || true
            podman machine rm -f "$m" 2>/dev/null || true
        done
        echo -e "${GREEN}Old machines removed${NC}"
    fi
}

set_default_machine() {
    echo -e "${BLUE}Setting '$MACHINE_NAME' as default...${NC}"
    podman system connection default "$MACHINE_NAME" 2>/dev/null || true
}

print_summary() {
    local vm_hostname="$(hostname -s)-podman"

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Deployment Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Machine: $MACHINE_NAME (default)"
    if [ -n "$S1_PACKAGE" ]; then
        echo "Hostname: $vm_hostname"
    fi
    echo ""
    echo "Commands:"
    echo "  podman machine ssh $MACHINE_NAME"
    echo "  podman machine stop $MACHINE_NAME"
    echo ""
    if [ -n "$S1_PACKAGE" ]; then
        echo -e "${YELLOW}SentinelOne:${NC}"
        echo "  The agent sees process and file activity from containers"
        echo "  (execs, mounts, and files inside image layers are scanned)."
        echo ""
        echo "  Whether it labels them with container context is unverified:"
        echo "  the agent knows docker/containerd/kubernetes, not podman."
        echo "  Podman does expose a Docker compatible API at /run/docker.sock,"
        echo "  which is the endpoint the agent has built in - confirm with"
        echo "  SentinelOne support whether their Linux agent uses it."
        echo ""
        echo "SentinelOne console - search: $vm_hostname"
        if [ "$PRESERVE" = "true" ] && [ -n "$BACKUP_SITE_KEY" ]; then
            echo ""
            echo -e "${YELLOW}  The replaced machine is still registered.${NC}"
            echo "  Its agent identity could not come with it: anti-tamper protects"
            echo "  /opt/sentinelone/configuration, and a copied UUID registers as a"
            echo "  cloned agent. The new machine registered itself instead, so the"
            echo "  console now holds two endpoints called $vm_hostname."
            echo "  Decommission the older one - site key ${BACKUP_SITE_KEY}."
        fi
    fi
}

main() {
    parse_args "$@"

    echo ""
    echo -e "${BLUE}Podman Machine Deployment${NC}"
    echo ""

    # Both halves are usable on their own, which is also how the test suite
    # drives them.
    case "$MODE" in
        backup)
            backup_machine
            echo ""
            echo -e "${GREEN}Backup complete: $BACKUP_DIR${NC}"
            echo "Restore it with: $0 --restore $BACKUP_DIR"
            exit 0
            ;;
        restore)
            restore_machine "$BACKUP_DIR"
            exit $?
            ;;
    esac

    check_prerequisites
    prompt_for_token
    cleanup_old_machines
    if [ "$PRESERVE" = "true" ]; then
        backup_machine
    fi
    create_machine
    deploy_sentinelone
    set_default_machine
    if [ "$PRESERVE" = "true" ] && [ -n "$BACKUP_DIR" ]; then
        restore_machine "$BACKUP_DIR" || RESTORE_STATUS=1
    fi
    print_summary
    exit "$RESTORE_STATUS"
}

main "$@"
