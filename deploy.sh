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

# Fixed machine name
MACHINE_NAME="podman-machine-default"

# Defaults
S1_TOKEN=""
CPUS="4"
MEMORY="4096"
DISK_SIZE="100"
IMAGE_PATH=""
INTERACTIVE=false

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
  --help, -h           Show this help

Examples:
  $0
  $0 --token eyJ... --cpus 8 --memory 8192
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
            read -p "Remove existing machine and create new one? [y/N]: " answer
            if [[ "$answer" =~ ^[Yy] ]]; then
                echo -e "${YELLOW}Removing existing machine...${NC}"
                podman machine stop "$MACHINE_NAME" 2>/dev/null || true
                podman machine rm -f "$MACHINE_NAME" 2>/dev/null || true
            else
                echo -e "${BLUE}Keeping existing machine. Exiting.${NC}"
                exit 0
            fi
        else
            # Non-interactive mode - fail with helpful message
            echo -e "${RED}Error: Machine already exists.${NC}"
            echo "Run interactively to remove, or manually remove with:"
            echo "  podman machine stop $MACHINE_NAME"
            echo "  podman machine rm -f $MACHINE_NAME"
            exit 1
        fi
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
    fi
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
