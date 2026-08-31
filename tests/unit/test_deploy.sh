#!/bin/bash
#
# Layer 1c - the decisions inside deploy.sh that nothing else would notice.
#
# The migration round trip is proven on a real machine by the migration layer.
# What is checked here is cheap and catches the things a refactor quietly undoes:
# a secret that starts being written to disk, a kind node that starts being
# treated as ordinary cargo.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

DEPLOY="$(cat "$ROOT/deploy.sh")"

test_script_parses() {
    if bash -n "$ROOT/deploy.sh" 2>/dev/null; then
        t_pass "deploy.sh parses"
    else
        t_fail "deploy.sh parses" "$(bash -n "$ROOT/deploy.sh" 2>&1)"
    fi
}

test_backup_never_writes_the_token() {
    # The site key identifies the endpoint to decommission and is safe to keep.
    # The registration token is a secret and comes from --token every time.
    assert_contains "$DEPLOY" 'BACKUP_SITE_KEY="$site_key"' \
        "the backup records the site key"
    assert_not_contains "$DEPLOY" 'S1_TOKEN" > "$BACKUP' \
        "the backup does not write the registration token"
    assert_not_contains "$DEPLOY" '"token": ' \
        "the manifest has no token field"
}

test_kind_nodes_are_left_behind() {
    # A kind node is a running kubelet with etcd behind it; replaying its
    # definition does not give back a working cluster.
    assert_contains "$DEPLOY" "--filter label=io.x-k8s.kind.cluster" \
        "the backup identifies kind nodes"
    assert_contains "$DEPLOY" 'comm -23 "$DIR/all.txt" "$DIR/skipped.txt"' \
        "kind nodes are excluded from what gets exported"
}

test_containers_are_generated_one_per_pod() {
    # "podman kube generate a b" would put a and b in one pod and hand them a
    # shared network namespace they never had.
    assert_contains "$DEPLOY" 'podman kube generate --podman-only "$c" > "$DIR/containers/$c.yaml"' \
        "each container gets its own definition"
    assert_contains "$DEPLOY" "--podman-only" \
        "the definition keeps what plain Kubernetes YAML cannot express"
    assert_contains "$DEPLOY" "podman kube play --no-pod-prefix" \
        "the restored container keeps its own name"
    assert_contains "$DEPLOY" 'podman rename "${c}-pod-${c}" "$c"' \
        "and a podman without that flag is still handled"
}

test_backup_is_only_discarded_after_verification() {
    # Deleting it anywhere else would be deleting the only copy.
    local after_verify
    after_verify=$(printf '%s' "$DEPLOY" | sed -n '/VERIFY_OK/,/^}/p')
    assert_contains "$after_verify" "discard_backup" \
        "the backup is discarded on the verified path only"
    assert_contains "$DEPLOY" 'if [ "$KEEP_BACKUP" = "true" ]' \
        "--keep-backup overrides the deletion"
    assert_contains "$DEPLOY" '"$BACKUP_ROOT"/*)' \
        "only directories under the backup root are ever removed"
}

test_transient_containers_do_not_fail_the_backup() {
    # The container list is a snapshot; a --rm container can exit between the
    # listing and the export. That must not cost the images and volumes.
    assert_contains "$DEPLOY" 'echo "$c" >> "$DIR/ungenerated.txt"' \
        "a container that cannot be generated is recorded"
    assert_contains "$DEPLOY" 'comm -23 "$DIR/containers.txt" "$DIR/ungenerated.txt"' \
        "and dropped from what the restore is promised"
}

test_backup_leaves_containers_as_it_found_them() {
    # --backup-only replaces nothing, so it must not leave everything stopped.
    assert_contains "$DEPLOY" 'xargs -r podman start < "$DIR/running.txt"' \
        "containers stopped for the export are started again"
}

run_tests
