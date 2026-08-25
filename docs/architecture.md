# Architecture

How a `podman machine` works on macOS, what this image changes, and why.

## The pieces

```
macOS
├── podman (CLI)                  talks to the VM over ssh / the API socket
├── vfkit                         Apple Virtualization framework wrapper
│   └── the VM  ── virtio-blk ──  podman-debian-arm64.raw   (this image)
│                ── virtio-fs ──  /Users, /private, /var/folders, Rosetta
│                ── vsock 1024 ── Ignition config (first boot only)
│                ── vsock 1025 ── "Ready" signal
└── gvproxy                       user-mode network + port forwarding
```

`podman machine init` copies the image, `podman machine start` launches vfkit and
gvproxy, and then waits for the guest to say it is ready. Everything the host
needs from the guest - the user, its ssh key, the sockets - is delivered once, on
first boot, as an Ignition config over vsock port 1024.

## What the guest does on first boot

Fedora CoreOS has Ignition built in. Debian does not, so the image ships a small
provider that does the same job:

1. `ignition-provider.service` fetches the config from vsock port 1024 and
   applies it: creates the `core` user with the UID and ssh key podman chose,
   writes files, links and systemd units, sets the hostname.
   It skips three units podman sends that do not belong on Debian - see
   [Podman 6 and /etc/containers](#podman-6-and-etccontainers).
2. `post-ignition-setup.service` fills the gaps Ignition does not cover:
   passwordless sudo, subuid/subgid if Ignition did not set them, ssh socket
   forwarding, journal access for the machine user, and a `policy.json` fallback.
3. `podman-machine-ready.service` waits for Ignition, the network and sshd, then
   sends `Ready` to the host over vsock port 1025. `podman machine start` returns
   at that moment.

A marker file (`/var/lib/ignition-provider-complete`) keeps step 1 from running
again; podman only serves the config once.

## The root filesystem

Debian's cloud image ships ext4. The build converts it to **btrfs** with
`btrfs-convert`, then rewrites the bootloader to match:

- `/etc/fstab` gets `btrfs`, `compress=zstd`, `noatime`
- the EFI stub config on the ESP and `/boot/grub/grub.cfg` are pointed at the
  new filesystem UUID, with `insmod btrfs` and the partition number `virt-resize`
  produced
- the `ext2_saved` rollback subvolume is deleted and the initramfs regenerated

The build verifies this twice - after the conversion and again after the guest is
customised, because installing a kernel regenerates `grub.cfg`. Getting it wrong
produces an image that builds cleanly and then sits at a GRUB rescue prompt with
an empty console, which is why the check is a hard gate.

Podman then uses the btrfs graph driver: each image layer is a subvolume and each
container a snapshot, so there is no overlay and no FUSE in the path.
`storage.conf` asks for `driver_priority = ["btrfs", "overlay"]` rather than
pinning btrfs, so a store that lands somewhere else - `/tmp` is tmpfs - falls
back instead of failing.

## Kernel and container stack

| | Debian stable | this image |
|---|---|---|
| kernel | 6.12 | **7.1** from trixie-backports |
| podman | 5.4.2 | **5.8.4** from unstable |
| crun | 1.21 | **1.28** from unstable |
| netavark / aardvark-dns | 1.14 | **1.17** from unstable |

Backports carries no container packages for trixie - only the kernel - so the
container stack comes from unstable, pinned to priority 100 so nothing else
drifts and only those five packages are taken explicitly.

Neither backports nor unstable is covered by Debian's security team. That is a
deliberate trade for a current runtime, and it is written down next to the code
that makes it in `resources/install.sh`.

## x86_64 containers

Two paths exist, and the image prefers the fast one:

- **Rosetta** - Apple's translator, exposed to the VM as a virtio-fs share.
  `rosetta-activate.sh` mounts it, registers the binfmt handler and unregisters
  qemu's. It must run *after* `systemd-binfmt.service`, which flushes the whole
  binfmt table and re-registers only what it finds in `/usr/lib/binfmt.d`.
- **qemu-user** - emulation, ~450 MB in the image, used when Rosetta is not
  there (an Intel Mac, or a machine created without it).

Rosetta is decided when the machine is created, from `[machine] rosetta = true`
in the host's `containers.conf`. Podman re-derives it on every start, so the
setting has to live in the real config file - `deploy.sh` puts it there.

## Podman 6 and /etc/containers

Podman 6 ships an `etc-containers.mount` unit in its Ignition config that mounts
the host's `~/.config/containers` over `/etc/containers` inside the VM. On a
CoreOS machine that shares the host's registry configuration; on this image it
hides everything the image put there, and the guest runs podman 5.8, which reads:

- `storage.conf` - without it the storage driver falls back to overlay
- `containers.conf` - runtime, netns and dns settings silently ignored
- `policy.json` - **no image can be pulled at all**
- `podman-machine` - the marker podman uses to recognise it runs inside a
  machine; without it **no published port is ever forwarded to the host**

The Ignition provider therefore does not apply that unit. The host's registry
configuration still reaches the VM through the `registries.conf.d` symlink the
provider creates over the `/Users` mount. Credentials from the host's
`auth.json` are not shared into the VM; the remote client sends them with the
request instead.

The same provider also skips `immutable-root-on/off.service`, which run
`chattr -i /` for CoreOS's immutable root and only ever fail on Debian, leaving a
permanently failed unit that hides real ones.

## Where SentinelOne fits

The agent is installed into the running machine at deployment time, not into the
image - it is licensed per endpoint and not redistributable. `deploy.sh` uploads
the `.deb`, installs it, sets the hostname to `<mac-hostname>-podman` so the
machine is identifiable in the console, optionally applies a site token, and
starts the service.

What the agent sees today: process and file activity from containers, including
the scanner walking files inside image layers. Whether it labels those events
with container context is unresolved - the agent knows docker, containerd and
kubernetes, and has no podman or cri-o strings in it, but it does carry
`unix:///var/run/docker.sock`, which podman also serves. See `TODO.md`.
