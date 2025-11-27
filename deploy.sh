#!/bin/bash
#
# Podman Machine Deployment Script
#
# Creates a Podman machine with custom image and deploys SentinelOne agent.
#
# Usage:
#   ./deploy.sh <machine-name> [--token <s1-token>] [--cpus N] [--memory N] [--disk-size N]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
MACHINE_NAME=""
S1_TOKEN=""
CPUS="4"
MEMORY="4096"
DISK_SIZE="100"
IMAGE_PATH="$SCRIPT_DIR/output/podman-debian.raw.zst"
INTERACTIVE=false

usage() {
    cat << EOF
Usage: $0 <machine-name> [OPTIONS]

Create a secured Podman machine with SentinelOne agent.

Arguments:
  machine-name         Name for the Podman machine

Options:
  --token, -t TOKEN    SentinelOne registration token (prompts if not provided)
  --cpus N             Number of CPUs (default: 4)
  --memory N           Memory in MB (default: 4096)
  --disk-size N        Disk size in GB (default: 100)
  --image PATH         Path to image (default: output/podman-debian.raw.zst)
  --help, -h           Show this help

Examples:
  $0 dev-machine
  $0 prod --token eyJ... --cpus 8 --memory 8192
EOF
}

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --help|-h) usage; exit 0 ;;
        esac
    done

    [ $# -eq 0 ] && { usage; exit 1; }

    MACHINE_NAME="$1"; shift

    while [ $# -gt 0 ]; do
        case "$1" in
            --token|-t) S1_TOKEN="$2"; shift 2 ;;
            --cpus) CPUS="$2"; shift 2 ;;
            --memory) MEMORY="$2"; shift 2 ;;
            --disk-size) DISK_SIZE="$2"; shift 2 ;;
            --image) IMAGE_PATH="$2"; shift 2 ;;
            *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
        esac
    done
}

check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"

    command -v podman &>/dev/null || { echo -e "${RED}Error: podman not found${NC}"; exit 1; }

    [ -f "$IMAGE_PATH" ] || { echo -e "${RED}Error: Image not found: $IMAGE_PATH${NC}"; exit 1; }

    S1_PACKAGE=$(find "$SCRIPT_DIR/install" -name "SentinelAgent*.deb" -type f 2>/dev/null | head -1)
    [ -z "$S1_PACKAGE" ] && { echo -e "${RED}Error: No SentinelAgent*.deb in install/${NC}"; exit 1; }

    echo -e "${GREEN}OK${NC} - Image: $(basename "$IMAGE_PATH"), S1: $(basename "$S1_PACKAGE")"
}

create_machine() {
    export CONTAINERS_MACHINE_PROVIDER=applehv

    if podman machine list --format "{{.Name}}" 2>/dev/null | grep -q "^${MACHINE_NAME}$"; then
        echo -e "${YELLOW}Machine '$MACHINE_NAME' exists. Removing...${NC}"
        podman machine rm -f "$MACHINE_NAME" 2>/dev/null || true
    fi

    echo -e "${BLUE}Creating machine '$MACHINE_NAME'...${NC}"
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

    echo -e "${GREEN}Machine is running${NC}"
}

deploy_sentinelone() {
    local package_name=$(basename "$S1_PACKAGE")

    echo -e "${BLUE}Deploying SentinelOne...${NC}"

    # Set hostname based on machine name
    echo "  Setting hostname: $MACHINE_NAME"
    podman machine ssh "$MACHINE_NAME" "sudo bash -c '
        echo \"$MACHINE_NAME\" > /etc/hostname
        hostname \"$MACHINE_NAME\"
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
        podman machine ssh "$MACHINE_NAME" "sudo bash -c '
            /opt/sentinelone/bin/sentinelctl management token set \"$S1_TOKEN\" 2>/dev/null || true
            systemctl enable sentinelone 2>/dev/null || true
            systemctl start sentinelone 2>/dev/null || true
        '"
    fi

    # Cleanup
    podman machine ssh "$MACHINE_NAME" "rm -f /tmp/$package_name" 2>/dev/null || true

    echo -e "${GREEN}Done${NC}"
}

prompt_for_token() {
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
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Deployment Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Machine: $MACHINE_NAME (default)"
    echo "Hostname: $MACHINE_NAME"
    echo ""
    echo "Commands:"
    echo "  podman machine ssh $MACHINE_NAME"
    echo "  podman machine stop $MACHINE_NAME"
    echo ""
    echo "SentinelOne console - search: $MACHINE_NAME"
}

main() {
    parse_args "$@"

    echo ""
    echo -e "${BLUE}Podman Machine Deployment${NC}"
    echo ""

    check_prerequisites
    prompt_for_token
    cleanup_old_machines
    create_machine
    deploy_sentinelone
    set_default_machine
    print_summary
}

main "$@"
