#!/bin/bash
#
# Layer 4d - Kubernetes on top of the machine.
#
# Two paths, both of which have broken here:
#   podman kube play - podman's own Kubernetes YAML support, entirely in the guest
#   kind             - a real cluster in containers, driven from macOS
#
# kind is the harsher test: it needs podman logs to work (it waits for the node to
# log that systemd reached multi-user), and it needs the API server's published
# port to reach the host. Both were broken at different times, each with a symptom
# that pointed nowhere near the cause.
#
# The kind part is opt-in - it pulls a ~1 GB node image and takes minutes:
#   RUN_KIND=1 ./tests/integration/test_kubernetes.sh

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

MACHINE=$(guest_machine) || exit 1
KIND_CLUSTER="${KIND_CLUSTER:-s1-test-kind}"
printf 'Testing guest: %s\n' "$MACHINE"

test_kube_play() {
    local yaml_pod="s1kube$$"
    local out
    out=$(guest_script <<EOS 2>&1 | tr -d '\r'
cat > /tmp/$yaml_pod.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: $yaml_pod
spec:
  containers:
  - name: probe
    image: docker.io/library/alpine:latest
    command: ["sh", "-c", "echo KUBE_PLAY_OK; sleep 3"]
YAML
podman kube play /tmp/$yaml_pod.yaml >/dev/null 2>&1 && echo PLAYED || echo FAILED
sleep 4
podman logs ${yaml_pod}-probe 2>&1 | tail -2
podman kube down /tmp/$yaml_pod.yaml >/dev/null 2>&1
rm -f /tmp/$yaml_pod.yaml
EOS
)
    assert_contains "$out" "PLAYED" "podman kube play accepts a pod manifest"
    assert_contains "$out" "KUBE_PLAY_OK" "the pod ran and its logs are readable"
}

test_kind_cluster() {
    if [ "${RUN_KIND:-0}" != "1" ]; then
        t_skip "kind cluster comes up and is usable from macOS" "set RUN_KIND=1 (slow, pulls ~1 GB)"
        return
    fi
    if ! command -v kind >/dev/null 2>&1; then
        t_skip "kind cluster comes up and is usable from macOS" "kind is not installed on the host"
        return
    fi

    local kubectl_bin
    kubectl_bin=$(command -v kubectl 2>/dev/null)
    if [ -z "$kubectl_bin" ] || [ ! -x "$kubectl_bin" ]; then
        # Podman Desktop keeps its own copy when /usr/local/bin/kubectl is a
        # leftover symlink from an uninstalled Docker Desktop.
        kubectl_bin="$HOME/.local/share/containers/podman-desktop/extensions-storage/podman-desktop.kubectl-cli/bin/kubectl"
    fi

    export KIND_EXPERIMENTAL_PROVIDER=podman
    kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true

    if kind create cluster --name "$KIND_CLUSTER" >/dev/null 2>&1; then
        t_pass "kind creates a cluster on podman"
    else
        t_fail "kind creates a cluster on podman" \
            "if this says 'could not find a log line that matches Reached target Multi-User System', podman logs is empty in the guest"
        kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
        return
    fi

    if [ ! -x "$kubectl_bin" ]; then
        t_skip "the cluster answers from macOS" "no usable kubectl on the host"
    else
        local nodes
        nodes=$("$kubectl_bin" --context "kind-$KIND_CLUSTER" get nodes --no-headers 2>&1 | head -2)
        assert_contains "$nodes" "Ready" "the control plane node is Ready as seen from macOS"

        local pods
        pods=$("$kubectl_bin" --context "kind-$KIND_CLUSTER" get pods -A --no-headers 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' ')
        assert_eq "Running " "$pods" "every system pod is Running"
    fi

    kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
    t_pass "the cluster was removed again"
}

run_tests
