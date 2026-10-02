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

test_token_never_on_a_command_line() {
    # Anything in the ssh command line is in every "ps" on the Mac while it runs.
    assert_not_contains "$DEPLOY" 'token set \"$S1_TOKEN\"' \
        "the token is not interpolated into the ssh command"
    assert_contains "$DEPLOY" "printf '%s' \"\$S1_TOKEN\" | podman machine ssh" \
        "the token goes over stdin"
}

# The backup script as the guest runs it, against a podman stand-in. The machine
# is only replaced on BACKUP_OK, so this is the line that decides whether
# "podman machine rm" may take the only copy of someone's data.
run_backup_script() {
    local stub="$1" dir="$2" bin
    bin=$(mktemp -d)
    printf '%s\n' '#!/bin/bash' "$stub" > "$bin/podman"
    chmod +x "$bin/podman"
    { echo "DIR=$dir"
      printf '%s\n' "$DEPLOY" | awk "/^BACKUP_GUEST_SCRIPT='/{f=1;next} f&&/^'\$/{exit} f"
    } | PATH="$bin:$PATH" bash -s 2>&1
    rm -rf "$bin"
}

test_backup_is_complete_only_when_it_says_so() {
    local tmp out
    tmp=$(mktemp -d)

    out=$(run_backup_script 'case "$1" in images) echo "docker.io/library/alpine:latest";; esac; exit 0' "$tmp/ok")
    assert_contains "$out" "BACKUP_OK" "a backup that ran to the end says BACKUP_OK"
    assert_not_contains "$out" "BACKUP_FAIL" "and reports no failure"

    out=$(run_backup_script '[ "$1" = info ] && exit 125; exit 0' "$tmp/dead")
    assert_contains "$out" "BACKUP_FAIL" "a podman that does not answer fails the backup"
    assert_not_contains "$out" "BACKUP_OK" "and it never claims to be complete"

    out=$(run_backup_script '[ "$1" = volume ] && exit 1; exit 0' "$tmp/partial")
    assert_contains "$out" "BACKUP_FAIL list volumes" "a listing that fails is reported"
    rm -rf "$tmp"

    assert_contains "$DEPLOY" 'grep -qx "BACKUP_OK"' "the host requires BACKUP_OK"
    assert_contains "$DEPLOY" '|| rc=$?' "and checks the script's exit status"
}

test_rootful_machines_back_up_roots_store() {
    # Backing up the machine user's store on a rootful machine succeeds, finds
    # nothing, and lets the machine - with all of root's containers - go.
    assert_contains "$DEPLOY" "{{.Rootful}}" "deploy.sh asks whether the machine is rootful"
    assert_contains "$DEPLOY" '"${GUEST_SUDO}bash -s"' "the guest scripts can run as root"
    assert_contains "$DEPLOY" 'rootful.txt' "the backup records which store it came from"
    assert_contains "$DEPLOY" "init_args+=(--rootful)" "a rootful machine is replaced by a rootful one"
}

test_interactivity_comes_from_the_terminal() {
    # It was set only while asking for the token, so the offer to remove old
    # machines never appeared with --token or without an agent package.
    assert_matches "$(printf '%s\n' "$DEPLOY" | awk '/^main\(\)/,/^}/')" 'if \[ -t 0 \]; then' \
        "main decides interactivity from the terminal"
}

test_options_without_a_value_are_refused() {
    # "--token" as the last argument used to end the script silently under
    # set -e, and "--token --cpus 4" took "--cpus" as the token.
    local out rc
    out=$(bash "$ROOT/deploy.sh" --token 2>&1); rc=$?
    assert_contains "$out" "--token needs a value" "a trailing --token is reported"
    assert_eq 1 "$rc" "and fails"
    out=$(bash "$ROOT/deploy.sh" --token --cpus 4 2>&1)
    assert_contains "$out" "--token needs a value" "an option is not taken as a value"
    out=$(bash "$ROOT/deploy.sh" --cpus four 2>&1)
    assert_contains "$out" "--cpus needs a whole number" "numbers are checked"
    out=$(bash "$ROOT/deploy.sh" --restore 2>&1)
    assert_contains "$out" "--restore needs a value" "--restore without a directory is reported"
}

test_pod_members_get_their_names_back() {
    # podman 5.4 has no --no-pod-prefix and names a pod member <pod>-<name>;
    # the restore only knew the standalone form <name>-pod-<name>.
    assert_contains "$DEPLOY" 'podman rename "${pod}-${c}" "$c"' \
        "pod members are renamed back after kube play"
    assert_contains "$DEPLOY" 'podman rename "${c}-pod-${c}" "$c"' \
        "and standalone containers still are"
}

test_verify_refuses_a_backup_without_its_lists() {
    # A loop over a missing file runs zero times, so an empty directory used to
    # verify as a complete restore - and then get deleted.
    local tmp out bin
    tmp=$(mktemp -d); bin=$(mktemp -d)
    printf '#!/bin/sh\nexit 0\n' > "$bin/podman"; chmod +x "$bin/podman"
    out=$( { echo "DIR=$tmp"
             printf '%s\n' "$DEPLOY" | awk "/^VERIFY_GUEST_SCRIPT='/{f=1;next} f&&/^'\$/{exit} f"
           } | PATH="$bin:$PATH" bash -s 2>&1)
    rm -rf "$tmp" "$bin"
    assert_contains "$out" "VERIFY_FAILED" "an empty backup directory does not verify"
    assert_contains "$out" "MISSING backup file expected.txt" "and says what is missing"
    assert_contains "$DEPLOY" 'has no manifest.json - not a complete backup' \
        "restore refuses a directory without a manifest"
}

test_restore_starts_only_what_was_running() {
    # kube play started everything it created: two containers on one port - one
    # normally stopped - collided, and stopped ones ran for a moment.
    assert_contains "$DEPLOY" 'podman kube play --start=false --no-pod-prefix' \
        "the restore creates without starting"
    assert_contains "$DEPLOY" 'done < "$DIR/running.txt"' "and starts only what was running"
    assert_not_contains "$DEPLOY" 'podman stop -t 5 "$c"' "instead of stopping the rest afterwards"
}

test_backup_survives_a_prune_and_says_so() {
    # A prune while the backup had everything stopped took all 29 containers of
    # a real machine, and the backup - generating last - noticed nothing.
    local guest gen_line stop_line out tmp bin
    guest=$(printf '%s\n' "$DEPLOY" | awk "/^BACKUP_GUEST_SCRIPT='/{f=1;next} f&&/^'\$/{exit} f")
    gen_line=$(printf '%s\n' "$guest" | grep -n 'podman kube generate --podman-only "$c"' | head -1 | cut -d: -f1)
    stop_line=$(printf '%s\n' "$guest" | grep -n 'podman stop -t 10 "$c"' | head -1 | cut -d: -f1)
    assert_ne "" "$gen_line" "the backup generates definitions"
    [ -n "$gen_line" ] && [ -n "$stop_line" ] && [ "$gen_line" -lt "$stop_line" ] \
        && t_pass "definitions are generated before anything is stopped" \
        || t_fail "definitions are generated before anything is stopped" "generate at $gen_line, stop at $stop_line"
    assert_contains "$guest" "disappeared during the backup" \
        "a container that vanishes during the backup fails it"
    assert_contains "$guest" 'BACKUP_FAIL cannot generate $c' \
        "and so does one that exists but cannot be generated"

    # podman stop/start act on nothing when one name is missing, so a single
    # exited --rm container left every volume being written during the export.
    assert_not_contains "$guest" "xargs -r podman stop" "containers are stopped one at a time"
    assert_not_contains "$guest" "xargs -r podman start" "and started one at a time"

    # A container that exists and cannot be generated, against a stand-in podman.
    tmp=$(mktemp -d); bin=$(mktemp -d)
    cat > "$bin/podman" <<'STUB'
#!/bin/sh
case "$1 $2" in
    "ps -a") case "$*" in *label=*) ;; *Pod*) printf '\tweb\n' ;; *) echo web ;; esac ;;
    "kube generate") exit 1 ;;
    "container exists") exit 0 ;;
esac
exit 0
STUB
    chmod +x "$bin/podman"
    out=$( { echo "DIR=$tmp"; printf '%s\n' "$guest"; } | PATH="$bin:$PATH" bash -s 2>&1)
    rm -rf "$tmp" "$bin"
    assert_contains "$out" "BACKUP_FAIL cannot generate web" "an existing container that cannot be generated fails the backup"
}

test_kind_nodes_are_left_behind() {
    # A kind node is a running kubelet with etcd behind it; replaying its
    # definition does not give back a working cluster.
    assert_contains "$DEPLOY" "--filter label=io.x-k8s.kind.cluster" \
        "the backup identifies kind nodes"
    assert_contains "$DEPLOY" 'comm -23 "$DIR/all.txt" "$DIR/skipped.txt"' \
        "kind nodes are excluded from what gets exported"
}

test_pods_are_taken_whole() {
    # podman refuses to generate a container that belongs to a pod - "use
    # generate on the pod itself" - and never generates an infra container. A
    # backup that only walked containers silently dropped every composed
    # application it met, which is exactly what happened.
    assert_contains "$DEPLOY" 'podman kube generate --podman-only "$pod" > "$DIR/containers/pod-$pod.yaml"' \
        "pods are generated as pods"
    assert_contains "$DEPLOY" 'podman kube generate --podman-only "$c" > "$DIR/containers/ctr-$c.yaml"' \
        "and only containers outside any pod individually"
    assert_contains "$DEPLOY" '{{.Pod}}\t{{.Names}}' \
        "the individual list is built from containers with no pod"
    assert_contains "$DEPLOY" '{{.PodName}}\t{{.IsInfra}}\t{{.Names}}' \
        "pod members are recorded, so infra is never promised back"
}

test_containers_are_generated_one_per_file() {
    # Generating several into one file would put unrelated containers in a pod
    # and hand them a network namespace they never shared.
    assert_contains "$DEPLOY" "--podman-only" \
        "the definition keeps what plain Kubernetes YAML cannot express"
    assert_contains "$DEPLOY" "podman kube play --start=false --no-pod-prefix" \
        "the restored container keeps its own name"
    assert_contains "$DEPLOY" 'podman rename "${c}-pod-${c}" "$c"' \
        "and a podman without that flag is still handled"
}

test_the_written_down_state_covers_what_was_dropped() {
    # The message points people at containers.json for whatever could not be
    # expressed. It was written from the already-filtered list, so it was empty
    # for exactly those containers - an escape hatch that was not one.
    local before_filter
    before_filter=$(printf '%s' "$DEPLOY" | sed -n '/carried.txt/,/pods.json/p')
    assert_contains "$before_filter" "podman container inspect" \
        "every carried container is inspected before anything is filtered out"
    assert_contains "$DEPLOY" "podman pod inspect" "and the pods too"
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
    # Everything that was running, not only what made it into the backup - a
    # backup that captured nothing used to leave every container stopped.
    assert_contains "$DEPLOY" 'done < "$DIR/running-all.txt"' \
        "every container that was running is started again"
    # Pod status is deliberately not used: podman calls a pod with some
    # containers down "Degraded", and reading that as stopped took the running
    # ones with it on restore. Starting a container brings its pod up anyway.
    assert_not_contains "$DEPLOY" "running-pods" \
        "pod run state is never second-guessed from the pod status"

    # Taken after the stop this list is always empty, the restore starts nothing,
    # and a backup silently leaves the machine down. That shipped once.
    local before_stop
    before_stop=$(printf '%s' "$DEPLOY" | sed -n "/^BACKUP_GUEST_SCRIPT=/,/podman pod stop/p")
    assert_contains "$before_stop" 'podman ps --format "{{.Names}}" | sort > "$DIR/running-all.txt"' \
        "the running list is captured before anything is stopped"
}

run_tests
