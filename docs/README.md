# Documentation

A Podman machine image for macOS built from Debian 13, with a btrfs root, a
current kernel and container stack, and room for a SentinelOne agent that is
installed at deployment time rather than baked in.

| | |
|---|---|
| [architecture.md](architecture.md) | how the image and the machine actually work |
| [build.md](build.md) | building an image, and what the build guarantees |
| [usage.md](usage.md) | day-to-day use, with examples |
| [deployment-jamf.md](deployment-jamf.md) | rolling it out to a fleet with Jamf Pro |
| [troubleshooting.md](troubleshooting.md) | symptoms, causes and what to check |
| [testing.md](testing.md) | the test suite |

## What this is

`podman machine` on macOS normally runs Fedora CoreOS. This project replaces that
with a Debian 13 image so the VM matches what the rest of the estate runs, and so
an endpoint agent can be installed in it.

The image provides:

- **btrfs root** with zstd compression; podman stores image layers as btrfs
  subvolumes rather than overlay directories
- **Kernel 7.1** from Debian backports instead of stable's 6.12
- **podman 5.8** with crun, netavark and aardvark-dns from Debian unstable,
  pinned so nothing else follows them in
- **Rosetta** as the primary path for x86_64 containers, with qemu-user as the
  fallback where Rosetta is unavailable
- **Ignition provider** so Podman Desktop and `podman machine` drive it exactly
  as they drive CoreOS
- **Room for SentinelOne**: the agent is installed when the machine is deployed,
  not built into the image

## Quick start

On a Mac with podman installed:

```bash
# one image, then one machine
INSTALL_SENTINELONE=0 make build          # on a Linux build host, see build.md
./deploy.sh --image output/podman-debian.raw.zst
```

`deploy.sh` creates the machine `podman-machine-default`, starts it, turns on
Rosetta, and installs the SentinelOne agent if a `SentinelAgent*.deb` sits next
to it. Everything after that is ordinary podman:

```bash
podman run --rm alpine echo hello
podman run -d -p 8080:80 nginx:alpine     # reachable at localhost:8080 on the Mac
podman run --rm --arch amd64 alpine uname -m   # x86_64, translated by Rosetta
```

## Licensing note

The SentinelOne agent is licensed per endpoint and is not redistributable, so it
is **not** part of any image that leaves the build host. `build.sh` defaults to
`INSTALL_SENTINELONE=0` for that reason. The agent reaches the machine at
deployment time from a copy the operator already holds - see
[deployment-jamf.md](deployment-jamf.md) for how that is delivered to a fleet.
