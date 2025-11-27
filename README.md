# Podman Machine with SentinelOne

Custom Debian-based Podman machine image with SentinelOne agent support for macOS.

## Overview

This project provides:
1. **Build script** - Creates Debian 13 image for Podman Desktop (runs on Linux server)
2. **Deploy script** - Creates Podman machine and installs SentinelOne (runs on Mac)

## Quick Start

### 1. Build Image (on Debian/Ubuntu server)

```bash
make install-deps  # Install libguestfs, qemu
make build         # Build image (~5-10 min)
# Output: output/podman-debian.raw.zst
```

### 2. Deploy Machine (on Mac)

Download `deploy.sh` and the image file to a directory:

```bash
mkdir ~/podman-deploy && cd ~/podman-deploy

# Copy files (from build server or shared location)
cp /path/to/podman-debian.raw.zst .
cp /path/to/SentinelAgent*.deb .  # Optional

# Deploy machine
chmod +x deploy.sh
./deploy.sh --token <s1-token>
```

The deploy script will:
- Auto-detect image and SentinelOne package in current directory
- Create Podman machine named `podman-machine-default`
- Start the machine and set as default
- Set VM hostname to Mac hostname (for SentinelOne identification)
- Install and register SentinelOne agent (if package present)

## Project Structure

```
s1-podman-secured/
├── build.sh           # Build script (Linux)
├── deploy.sh          # Deploy script (Mac) - standalone
├── Makefile
├── resources/         # VM configuration files
│   ├── scripts/       # Shell scripts and Python
│   ├── services/      # Systemd units
│   └── configs/       # Configuration files
├── output/            # Built image (gitignored)
├── debs/              # Downloaded packages (gitignored)
└── cache/             # Build cache (gitignored)
```

## Deploy Options

```bash
./deploy.sh [options]

Options:
  --token, -t TOKEN    SentinelOne token
  --cpus N             CPUs (default: 4)
  --memory N           Memory MB (default: 4096)
  --disk-size N        Disk GB (default: 100)
  --image PATH         Image path (default: auto-detect)
```

## Features

- **Rosetta Support**: x86_64 binary translation on Apple Silicon
- **Podman Desktop Compatible**: Full integration with Ignition provider
- **SentinelOne Integration**: Automatic agent installation and registration
- **Offline Build**: No network required during image customization

## Requirements

**Build server (Debian/Ubuntu):**
- libguestfs-tools
- qemu-system
- zstd
- debootstrap

**Mac:**
- Podman Desktop
- SentinelOne .deb package (optional)

## License

MIT
