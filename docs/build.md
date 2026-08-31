# Building the image

The build runs on **Linux with libguestfs**, not on macOS. It produces one file:
`output/podman-debian.raw.zst`, about 1.2 GB, plus its checksum.

## Requirements

```bash
sudo apt install -y libguestfs-tools qemu-utils qemu-system xz-utils zstd curl debootstrap
```

The build host must match the target architecture: an arm64 host builds an arm64
image. Roughly 45 GB of free disk and, on a machine without KVM, about an hour.

Building inside a podman machine works and is a practical option on a Mac - the
VM is Debian arm64 and libguestfs falls back to TCG:

```bash
podman machine ssh
sudo apt install -y libguestfs-tools qemu-utils qemu-system debootstrap zstd
mkdir ~/build && cd ~/build
cp -a /Users/<you>/path/to/repo/{build.sh,resources} .
sudo env LIBGUESTFS_BACKEND_SETTINGS=force_tcg ./build.sh
```

Copy the result back over the `/Users` share. Do not build in the machine you are
about to replace with the result without copying the image out first.

**Nothing may stop that machine while the build runs.** The build lives inside
it, so a `podman machine stop` from anywhere - Podman Desktop counts - takes the
whole thing with it. That looks like this in the guest's journal, an hour in:

```
systemd-logind: Powering off...
session-356.scope: Killing process 140704 (virt-resize) with signal SIGTERM
```

Run the build detached (`setsid nohup ./run-build.sh &`) so an ssh drop alone is
survivable, and leave the machine alone until it finishes.

## Running it

```bash
make build                      # LIBGUESTFS_BACKEND_SETTINGS=force_tcg ./build.sh
INSTALL_SENTINELONE=0 ./build.sh
VERBOSE=1 ./build.sh            # also prints the in-guest install log
DEBUG_BUILD=1 ./build.sh        # root password 'podman', console logging
IMAGE_SIZE=20G ./build.sh       # default 10G; the machine grows it at first boot
```

| Variable | Default | Meaning |
|---|---|---|
| `INSTALL_SENTINELONE` | `0` | bake the agent into the image. Off by default: the agent is licensed per endpoint and not redistributable |
| `SENTINELONE_TOKEN` | – | site token to bake in, only meaningful with the above |
| `IMAGE_SIZE` | `10G` | virtual disk size of the image itself |
| `ARCH` | `uname -m` | `aarch64` or `x86_64` |
| `VERBOSE` | `0` | stream the guest install log |
| `DEBUG_BUILD` | `0` | root password, serial console logging |

With `INSTALL_SENTINELONE=1` and no `SentinelAgent*.deb` next to `build.sh`, the
build fails rather than quietly producing an image without an agent.

## What the build does

1. Downloads the Debian 13 cloud image and verifies its SHA512.
2. Grows the partition to the image size with `virt-resize`.
3. Converts the root filesystem from ext4 to **btrfs** and rewrites `fstab`, the
   EFI stub config and `grub.cfg` for the new filesystem.
4. **Verifies the bootloader** - fails if any boot config still references the
   old UUID or does not reference the new one.
5. Downloads the package set into a debootstrap chroot and copies the `.deb`s
   plus the package list into the image.
6. Runs `resources/install.sh` inside the image: installs and **verifies every
   package on the list**, upgrades the container stack from unstable, replaces
   the kernel with the backports one, installs the provider, services and
   configuration, and drops the btrfs rollback subvolume.
7. **Verifies the bootloader again** - installing a kernel regenerates
   `grub.cfg` - and asserts exactly one kernel is left in `/boot`.
8. Converts to raw, compresses with zstd, writes the checksum.

## What the build refuses to ship

Each of these is a gate, because each corresponds to something that once shipped:

- a boot configuration pointing at the pre-conversion filesystem
- a package the build intended to install that is not actually installed
- more than one kernel, or none
- `INSTALL_SENTINELONE=1` without an agent package

## After building

Check the artifact before deploying it - no VM needed, takes seconds:

```bash
./tests/run.sh image
```

That reads the partition table, confirms the root filesystem is btrfs, and checks
that the GRUB stub on the EFI partition searches for the UUID the filesystem
actually has. See [testing.md](testing.md).

## Rebuilding when Debian moves

The container stack and the kernel float with unstable and backports, so two
things drift:

- **podman's version.** The vendored test suite is pinned to the podman in the
  image. After a rebuild, check `podman --version` in the machine and re-sync:
  `PODMAN_VERSION=vX.Y.Z ./tests/podman-system/sync.sh`. The suite runner warns
  when the two disagree.
- **the kernel.** `uname -r` in the machine should be 7.x; the integration tests
  assert it.
