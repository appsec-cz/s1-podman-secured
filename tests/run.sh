#!/bin/bash
#
# Test entry point.
#
#   ./tests/run.sh                 fast layers: unit + image + integration
#   ./tests/run.sh unit            one layer
#   ./tests/run.sh unit image      several
#   ./tests/run.sh all             everything, including the destructive layers
#   ./tests/run.sh machine         lifecycle on a throwaway machine (destructive)
#   ./tests/run.sh podman-system   podman's own suite in a throwaway machine (destructive)
#
# Environment:
#   TEST_IMAGE_PATH        image to test (default: newest in output/)
#   TEST_MACHINE_EXPLICIT  guest for the integration layer (default: the running machine)
#   TEST_MACHINE           throwaway machine name for the destructive layers
#   TEST_FILTER            substring filter on test function names
#   RUN_KIND=1             include the kind cluster test
#   KEEP_MACHINE=1         leave the throwaway machine behind for debugging
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

DEFAULT_LAYERS=(unit image integration)
ALL_LAYERS=(unit image integration machine podman-system)

layers=("$@")
if [ ${#layers[@]} -eq 0 ]; then
    layers=("${DEFAULT_LAYERS[@]}")
elif [ "${layers[0]}" = "all" ]; then
    layers=("${ALL_LAYERS[@]}")
fi

failed_layers=()
started=$(date +%s)

run_layer_unit() {
    local rc=0
    (cd "$HERE/unit" && python3 -m unittest discover -p 'test_*.py' -v 2>&1 | tail -5) || rc=1
    "$HERE/unit/test_resources.sh" || rc=1
    return $rc
}

run_layer_image() {
    "$HERE/image/test_artifact.sh"
}

run_layer_integration() {
    local rc=0 f
    for f in "$HERE"/integration/test_*.sh; do
        "$f" || rc=1
    done
    return $rc
}

run_layer_machine() {
    "$HERE/machine/test_lifecycle.sh"
}

run_layer_podman_system() {
    "$HERE/podman-system/run.sh"
}

for layer in "${layers[@]}"; do
    printf '\n%b╔══ %s ══╗%b\n' "$BOLD$BLUE" "$layer" "$NC"
    case "$layer" in
        unit)          run_layer_unit ;;
        image)         run_layer_image ;;
        integration)   run_layer_integration ;;
        machine)       run_layer_machine ;;
        podman-system) run_layer_podman_system ;;
        *) printf 'unknown layer: %s\n' "$layer"; exit 2 ;;
    esac || failed_layers+=("$layer")
done

elapsed=$(( $(date +%s) - started ))
printf '\n%b══ summary ══%b  (%ds)\n' "$BOLD" "$NC" "$elapsed"
if [ ${#failed_layers[@]} -eq 0 ]; then
    printf '%ball layers passed:%b %s\n' "$GREEN" "$NC" "${layers[*]}"
    exit 0
fi
printf '%bfailed layers:%b %s\n' "$RED" "$NC" "${failed_layers[*]}"
exit 1
