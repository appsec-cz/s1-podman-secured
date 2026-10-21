#!/bin/bash
# Transfer one volume without depending on the server's volume REST endpoints.
# Run as the macOS user who owns the machine (including from Jamf).
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: podman-volume-transfer.sh [OPTIONS] export|import VOLUME ARCHIVE
  --machine NAME   Machine name (default: podman-machine-default)
  --podman PATH    CLI path (default: podman on PATH)
  --rootful        Use root's volume store inside the VM
  --rootless       Use the SSH user's store inside the VM
Without a store override, use the machine's Rootful setting.
Import requires an existing volume; preserve its driver, labels and options
when creating it. Stop applications using the volume before either operation.
EOF
}

machine=podman-machine-default
cli=podman
store=auto
while [ $# -gt 0 ]; do
    case "$1" in
        --machine|--podman)
            [ $# -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
            if [ "$1" = --machine ]; then machine=$2; else cli=$2; fi
            shift 2 ;;
        --rootful) store=true; shift ;;
        --rootless) store=false; shift ;;
        --help|-h) usage; exit 0 ;;
        --*) usage >&2; exit 2 ;;
        *) break ;;
    esac
done
[ $# -eq 3 ] || { usage >&2; exit 2; }
action=$1 volume=$2 archive=$3
case "$action" in export|import) ;; *) usage >&2; exit 2 ;; esac
# Podman volume names contain only these characters. Besides rejecting options,
# this keeps names safe across the SSH command's extra round of shell parsing.
[[ "$volume" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || { echo 'Invalid volume name' >&2; exit 2; }
[ -n "$archive" ] || { echo 'Archive path is empty' >&2; exit 2; }
# An absolute path also keeps tar/mktemp from treating a filename as an option.
case "$archive" in /*) ;; *) archive="$PWD/$archive" ;; esac

if [ "$store" = auto ]; then
    store=$("$cli" machine inspect "$machine" --format '{{.Rootful}}')
    store=${store//$'\r'/}
fi
case "$store" in
    true) guest='sudo -n podman' ;;
    false) guest=podman ;;
    *) echo "Cannot determine rootful setting for $machine: $store" >&2; exit 1 ;;
esac

if ! "$cli" machine ssh "$machine" "$guest volume exists $volume"; then
    echo "Volume $volume is absent or inaccessible in the selected store; create it with its original settings first." >&2
    exit 1
fi

temporary=''
trap '[ -z "$temporary" ] || rm -f "$temporary"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$action" in
    export)
        # Keep an older good archive intact if SSH or export fails halfway.
        temporary=$(mktemp "${archive}.part.XXXXXX")
        "$cli" machine ssh "$machine" "$guest volume export $volume" > "$temporary"
        tar -tf "$temporary" >/dev/null
        mv -f "$temporary" "$archive"
        temporary=''
        ;;
    import)
        tar -tf "$archive" >/dev/null
        "$cli" machine ssh "$machine" "$guest volume import $volume -" < "$archive"
        ;;
esac
echo "Volume $action completed: $volume" >&2
