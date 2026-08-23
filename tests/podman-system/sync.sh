#!/bin/bash
#
# Vendor podman's own system test suite.
#
# The tests are pinned to the podman version that ships inside the image, so the
# suite always matches the podman under test. Re-run this after bumping Debian's
# podman: change PODMAN_VERSION, run ./sync.sh, review the diff.
#
# Upstream: https://github.com/containers/podman (Apache-2.0)
#
set -euo pipefail

PODMAN_VERSION="${PODMAN_VERSION:-v5.4.2}"
BASE="https://raw.githubusercontent.com/containers/podman/${PODMAN_VERSION}/test/system"
DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vendor"

# Helpers the suite cannot run without.
HELPERS=(
    helpers.bash
    helpers.network.bash
    helpers.registry.bash
    helpers.sig-proxy.bash
    helpers.systemd.bash
    setup_suite.bash
    README.md
)

# Test files that exercise something this image is responsible for.
# See VENDORED.md for why each is here and why the rest is not.
TESTS=(
    001-basic.bats              005-info.bats               010-images.bats
    011-image.bats              015-help.bats               020-tag.bats
    030-run.bats                035-logs.bats               040-ps.bats
    045-start.bats              050-stop.bats               055-rm.bats
    060-mount.bats              065-cp.bats                 070-build.bats
    075-exec.bats               080-pause.bats              085-top.bats
    090-events.bats             110-history.bats            120-load.bats
    125-import.bats             130-kill.bats               140-diff.bats
    160-volumes.bats            170-run-userns.bats         190-run-ipcns.bats
    195-run-namespaces.bats     200-pod.bats                220-healthcheck.bats
    250-systemd.bats            251-system-service.bats     252-quadlet.bats
    270-socket-activation.bats  271-tcp-cors-server.bats    272-system-connection.bats
    280-update.bats             300-cli-parsing.bats        320-system-df.bats
    400-unprivileged-access.bats 420-cgroups.bats           450-interactive.bats
    500-networking.bats         505-networking-pasta.bats   550-pause-process.bats
    600-completion.bats         610-format.bats             620-option-conflicts.bats
    700-play.bats               710-kube.bats               800-config.bats
    850-compose.bats            999-final.bats
)

mkdir -p "$DEST"
echo "Vendoring podman ${PODMAN_VERSION} system tests into ${DEST}"

fetch() {
    local name="$1"
    if ! curl -fsSL --retry 3 --max-time 60 -o "$DEST/$name" "$BASE/$name"; then
        echo "ERROR: failed to fetch $name" >&2
        return 1
    fi
}

for f in "${HELPERS[@]}" "${TESTS[@]}"; do
    fetch "$f"
    printf '  %s\n' "$f"
done

curl -fsSL --retry 3 --max-time 60 -o "$DEST/LICENSE" \
    "https://raw.githubusercontent.com/containers/podman/${PODMAN_VERSION}/LICENSE"

echo "$PODMAN_VERSION" > "$DEST/.podman-version"
echo "Done: $(ls -1 "$DEST"/*.bats | wc -l | tr -d ' ') test files, $(ls -1 "$DEST"/*.bash | wc -l | tr -d ' ') helpers"
