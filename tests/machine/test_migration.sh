#!/bin/bash
#
# Layer 3b - data across a machine replacement, on a throwaway machine.
# DESTRUCTIVE: it creates, destroys and recreates machines.
#
# "podman machine rm" takes the disk with it, so an image update used to cost
# every image, volume and container in the machine. deploy.sh --preserve exports
# them through podman's own formats and puts them back. This layer is the only
# thing that proves the round trip, because each half looks fine on its own:
# a backup that writes files, and a restore that reports success while the data
# it was meant to bring back is not actually there.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

machine_guard || exit 1

REPO_ROOT="$(cd "$HERE/../.." && pwd)"
DEPLOY="$REPO_ROOT/deploy.sh"
export PODMAN_MACHINE_NAME="$TEST_MACHINE"

MIG_IMG="${TEST_CONTAINER_IMAGE:-docker.io/library/alpine:latest}"
BACKUP_PATH=""

cleanup() {
    [ -n "$BACKUP_PATH" ] && [ -d "$BACKUP_PATH" ] && rm -rf "$BACKUP_PATH"
    machine_destroy
    machine_restore_running
}
trap cleanup EXIT

test_01_machine_with_data() {
    machine_stash_running
    if ! machine_create; then
        t_fail "throwaway machine created" "the image does not boot - run the lifecycle layer first"
        t_summary
        exit 1
    fi
    t_pass "throwaway machine created"

    # A pod with one member up and one down is the shape that broke: podman
    # refuses to generate a container that belongs to a pod, and calls such a pod
    # "Degraded" rather than running.
    machine_run_script <<EOS >/dev/null 2>&1
podman pull $MIG_IMG
podman volume create migvol --label purpose=migration
podman run -d --name migrunning -p 18099:80 -v migvol:/data --restart=always \
    $MIG_IMG sh -c 'echo MIGRATION_PAYLOAD > /data/marker; sleep 3600'
sleep 2
podman run -d --name migstopped $MIG_IMG sleep 3600
podman stop migstopped
podman pod create --name migpod -p 18098:80
podman run -d --pod migpod --name migpodup $MIG_IMG sleep 3600
podman run -d --pod migpod --name migpoddown $MIG_IMG sleep 3600
sleep 2
podman stop migpoddown
EOS

    local names
    names=$(machine_ssh "podman ps -a --format '{{.Names}}'" 2>/dev/null | tr -d '\r' | sort | tr '\n' ' ')
    assert_contains "$names" "migrunning" "a running container exists to be preserved"
    assert_contains "$names" "migstopped" "a stopped container exists to be preserved"
    assert_contains "$names" "migpodup" "a pod member is up"
    assert_contains "$names" "migpoddown" "and another is down, so the pod is Degraded"
}

# deploy.sh talks to a person, so its output is coloured; the path has to be dug
# out from under the escapes.
plain() { sed $'s/\033\[[0-9;]*m//g'; }

test_02_backup_writes_a_usable_set() {
    local out
    out=$("$DEPLOY" --backup-only 2>&1 | plain)
    BACKUP_PATH=$(printf '%s' "$out" | sed -n 's/^Backup complete: //p' | tail -1)

    if [ -z "$BACKUP_PATH" ] || [ ! -d "$BACKUP_PATH" ]; then
        t_fail "deploy.sh --backup-only produces a backup" "$out"
        t_summary
        exit 1
    fi
    t_pass "deploy.sh --backup-only produces a backup"

    assert_file_exists "$BACKUP_PATH/images.tar" "the image archive was written"
    assert_file_exists "$BACKUP_PATH/volumes/migvol.tar" "the volume was exported"
    assert_file_exists "$BACKUP_PATH/containers/ctr-migrunning.yaml" "the container definition was generated"
    assert_file_exists "$BACKUP_PATH/manifest.json" "the manifest was written"

    # One file each: generating several together would put unrelated containers
    # in a pod and hand them a network namespace they never shared.
    assert_file_exists "$BACKUP_PATH/containers/ctr-migstopped.yaml" "each container got its own definition"

    # The whole point of the pod case - a per-container generate fails here.
    assert_file_exists "$BACKUP_PATH/containers/pod-migpod.yaml" "the pod was generated as a pod"
    local ungenerated
    ungenerated=$(cat "$BACKUP_PATH/ungenerated.txt" "$BACKUP_PATH/ungenerated-pods.txt" 2>/dev/null)
    assert_eq "" "$ungenerated" "nothing was left behind as ungeneratable"

    # The escape hatch has to hold what was dropped, not what survived.
    if [ -s "$BACKUP_PATH/containers.json" ]; then
        t_pass "the recorded container state is not empty"
    else
        t_fail "the recorded container state is not empty" "containers.json is empty"
    fi
}

test_03_data_survives_a_replacement() {
    machine_destroy
    if ! machine_create; then
        t_fail "the machine was replaced" "the second machine did not come up"
        t_summary
        exit 1
    fi
    t_pass "the machine was replaced"

    local gone
    gone=$(machine_ssh "podman ps -a --format '{{.Names}}'; podman volume ls --format '{{.Name}}'" 2>/dev/null | tr -d '\r')
    assert_not_contains "$gone" "migvol" "the replacement machine really starts empty"

    local out
    out=$("$DEPLOY" --restore "$BACKUP_PATH" 2>&1 | plain)
    if printf '%s' "$out" | grep -q "Everything in the backup is back"; then
        t_pass "deploy.sh --restore reports a verified restore"
    else
        t_fail "deploy.sh --restore reports a verified restore" "$out"
    fi

    # The point of the whole exercise: the bytes in the volume.
    local marker
    marker=$(machine_ssh "podman run --rm -v migvol:/d $MIG_IMG cat /d/marker" 2>/dev/null | tr -d '\r')
    assert_contains "$marker" "MIGRATION_PAYLOAD" "the volume came back with its data"

    # kube play calls them <name>-pod-<name>; anything built around the original
    # names would break on the other side of an update.
    local names
    names=$(machine_ssh "podman ps -a --format '{{.Names}}'" 2>/dev/null | tr -d '\r' | sort | tr '\n' ' ')
    assert_contains "$names" "migrunning" "the container kept its original name"
    assert_not_contains "$names" "migrunning-pod-migrunning" "no pod-mangled name was left behind"

    local running
    running=$(machine_ssh "podman ps --format '{{.Names}}'" 2>/dev/null | tr -d '\r' | sort | tr '\n' ' ')
    assert_contains "$running" "migrunning" "what was running is running again"
    assert_not_contains "$running" "migstopped" "what was stopped is still stopped"

    local ports
    ports=$(machine_ssh "podman port migrunning" 2>/dev/null | tr -d '\r')
    assert_contains "$ports" "18099" "the published port came back"

    # A pod whose members were half up reads as "Degraded"; treating that as
    # stopped took the running member down with it on restore.
    assert_contains "$names" "migpodup" "the pod member came back"
    assert_contains "$running" "migpodup" "the member that was up is up again"
    assert_not_contains "$running" "migpoddown" "the member that was down stayed down"

    local pods
    pods=$(machine_ssh "podman pod ls --format '{{.Name}}'" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
    assert_contains "$pods" "migpod" "the pod itself came back under its own name"
}

test_04_verified_backup_is_discarded() {
    # A verified restore means the data exists twice and the copy in the machine
    # is the one that gets used. Leaving gigabytes behind is not a kindness.
    if [ -d "$BACKUP_PATH" ]; then
        t_fail "the backup is removed once the restore is verified" "still there: $BACKUP_PATH"
    else
        t_pass "the backup is removed once the restore is verified"
        BACKUP_PATH=""
    fi
}

run_tests
