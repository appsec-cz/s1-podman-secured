# Podman Machine with SentinelOne

A Debian 13 Podman machine image for macOS, with a btrfs root, a current kernel
and container stack, Rosetta for x86_64 workloads, and room for a SentinelOne
agent that is installed when the machine is deployed.

Full documentation is in **[docs/](docs/)**:

| | |
|---|---|
| [docs/architecture.md](docs/architecture.md) | how the image and the machine work |
| [docs/build.md](docs/build.md) | building an image |
| [docs/usage.md](docs/usage.md) | day-to-day use, with examples |
| [docs/deployment-jamf.md](docs/deployment-jamf.md) | rolling it out with Jamf Pro |
| [docs/troubleshooting.md](docs/troubleshooting.md) | symptoms and causes |
| [docs/testing.md](docs/testing.md) | the test suite |

## Quick start

**Build** on a Linux host with libguestfs (about an hour):

```bash
make install-deps
make build                       # output/podman-debian.raw.zst
```

**Deploy** on the Mac, from a directory holding the image and - if you have it -
your licensed agent package:

```bash
./deploy.sh                      # image and agent auto-detected
./deploy.sh --token <site-token> # and register the agent
```

That creates `podman-machine-default`, turns on Rosetta, installs the agent and
starts it. Everything after that is ordinary podman:

```bash
podman run --rm alpine echo hello
podman run -d -p 8080:80 nginx:alpine        # reachable on localhost:8080
podman run --rm --arch amd64 alpine uname -m # x86_64, translated by Rosetta
```

## What is in the image

- **btrfs root** with zstd compression; image layers are btrfs subvolumes
- **Kernel 7.1** from Debian backports
- **podman 5.8**, crun, netavark and aardvark-dns from Debian unstable, pinned
- **Rosetta** as the primary x86_64 path, qemu-user as the fallback
- **Ignition provider** so Podman Desktop and `podman machine` drive it like they
  drive Fedora CoreOS
- **No Docker Engine** - `docker` is podman, and podman serves the Docker API

Neither backports nor unstable is covered by Debian's security team. That trade
is deliberate and documented in [docs/architecture.md](docs/architecture.md).

## SentinelOne and licensing

The agent is licensed per endpoint and is not redistributable, so it is **not**
built into any image that leaves the build host - `build.sh` defaults to
`INSTALL_SENTINELONE=0`. It is installed into the machine at deployment time from
a copy you already hold, and reports itself as `<mac-hostname>-podman`.

For a fleet, both the image and the agent travel over Jamf as separate packages;
see [docs/deployment-jamf.md](docs/deployment-jamf.md).

## Testing

```bash
./tests/run.sh          # unit + image + integration, about two minutes
./tests/run.sh all      # everything, including podman's own suite
```

The `image` layer is worth running on every build: it catches an image that
builds cleanly and cannot boot, in seconds and without a VM. See
[docs/testing.md](docs/testing.md).

## Deploy options

```
./deploy.sh [options]

  --token, -t TOKEN    SentinelOne site token (prompts if interactive)
  --cpus N             CPUs (default: 4)
  --memory N           Memory in MB (default: 4096)
  --disk-size N        Disk in GB (default: 100)
  --image PATH         Image path (default: auto-detect in the current directory)
```

## Project layout

```
s1-podman-secured/
├── build.sh            image build (Linux, libguestfs)
├── deploy.sh           machine deployment (macOS, standalone)
├── docs/               documentation
├── resources/          what goes into the image
│   ├── scripts/        Ignition provider, post-boot setup, Rosetta activation
│   ├── services/       systemd units
│   └── configs/        podman, network, ssh, sysctl configuration
├── tests/              layered test suite, incl. podman's own vendored suite
├── output/             built image (gitignored)
├── debs/               downloaded packages (gitignored)
└── cache/              build cache (gitignored)
```

## Requirements

**Build host:** Debian or Ubuntu with `libguestfs-tools`, `qemu-system`,
`qemu-utils`, `debootstrap`, `zstd`.

**Mac:** podman 6.x (Podman Desktop optional), Apple Silicon for Rosetta.

## License

MIT. The SentinelOne agent is not covered by it and is not distributed here.
