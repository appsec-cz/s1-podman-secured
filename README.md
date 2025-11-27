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

Copy the image and SentinelOne package to your Mac, then:

```bash
# Place files
cp podman-debian.raw.zst output/
cp SentinelAgent*.deb install/

# Deploy machine
./deploy.sh --token <s1-token>
```

The deploy script will:
- Create Podman machine named `podman-machine-default`
- Start the machine and set as default
- Set VM hostname to Mac hostname (for SentinelOne identification)
- Install and register SentinelOne agent

## Files

| File | Description |
|------|-------------|
| `build.sh` | Build script (Linux) |
| `deploy.sh` | Deploy script (Mac) |
| `ignition-provider.py` | VM boot configuration |
| `install/` | Place SentinelOne .deb here |
| `output/` | Built image output |

## Deploy Options

```bash
./deploy.sh [options]

Options:
  --token, -t TOKEN    SentinelOne token
  --cpus N             CPUs (default: 4)
  --memory N           Memory MB (default: 4096)
  --disk-size N        Disk GB (default: 100)
  --image PATH         Image path
```

## Requirements

**Build server (Debian/Ubuntu):**
- libguestfs-tools
- qemu-system
- zstd

**Mac:**
- Podman Desktop
- SentinelOne .deb package

## License

MIT
