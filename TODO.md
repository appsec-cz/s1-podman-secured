# TODO - Future Improvements

Last reviewed: 2026-08-31

## Current Status

The image builds, boots and runs Podman Desktop workloads:

- Debian 13 with a **btrfs root** (zstd compression), converted at build time; the
  bootloader rewrite is verified by the build, which fails instead of shipping an
  image that cannot boot
- **Pure podman**, no Docker Engine; crun as the OCI runtime
- Every package the build intends to install is verified in the image, and the
  build fails if any is missing
- Podman 6 compatibility: its `etc-containers.mount` is not applied, so the
  machine keeps its own `/etc/containers` (see "Resolved" below for why)
- Ignition provider, ready signal, Rosetta, SentinelOne agent

Verified on a deployed machine: btrfs storage driver rootless and rootful, disk
grown to full size, published ports reachable from macOS, `podman logs` working,
a kind cluster created and driven from macOS, and one created through Podman
Desktop's own kind extension.

The machine also reports on itself at the end of every boot; see
[docs/troubleshooting.md](docs/troubleshooting.md#start-here).

## Open

### 1. SentinelOne container visibility - unresolved

The core question of the project is still open: **does the agent attribute
container context to what it sees?**

Evidence gathered on 2026-08-23 by inspecting the installed agent:

- it sees container activity already - execs, mount events, and the scanner walks
  files inside image layers
- its binary contains `docker` (37), `containerd` (13), `kubernetes` (40) and
  `kubelet` (12) strings, and **zero** occurrences of `podman`, `libpod`, `cri-o`
  or `crio`
- it has `unix:///var/run/docker.sock` built in, and a `namespaceDockerFilter`
  module
- rootless podman containers land in
  `/user.slice/user-501.slice/user@501.service/user.slice/libpod-<id>.scope`,
  rootful ones in `/machine.slice/libpod-<id>.scope`; the agent has no
  `machine.slice`/`user.slice`/`libpod` strings, so cgroup pattern matching will
  not find them

Podman exposes a Docker compatible API and the image already has
`/run/docker.sock -> podman.sock`, which is exactly the endpoint the agent knows.
Whether the agent actually uses it cannot be answered from here.

Next steps, in order:

1. register the agent with a site token, and give it a couple of minutes -
   `Connectivity` reads `Off` for a while after registration before it turns `On`
2. ask SentinelOne support whether their Linux agent discovers Podman through the
   Docker compatible socket, or through containerd
3. run a container and confirm in the console whether the event carries container
   context

Do not add Docker Engine for this. It was tried and removed: it never installed
(missing `tini` dependency), it conflicts with `podman-docker`, and the Ignition
config symlinks `/usr/local/bin/docker` to podman anyway, so `docker run` would
have kept going to podman regardless.

### 2. Docker compatibility on the macOS side

Inside the VM everything is in place: `/usr/bin/docker` (podman-docker),
`/run/docker.sock` and `/var/run/docker.sock` pointing at podman's socket, the
Docker API answering as `Podman Engine` at API 1.41, `--init` via catatonit,
short image names resolving.

On the host two pieces are missing, both left over from an uninstalled Docker
Desktop and both needing sudo:

- `/var/run/docker.sock` still points at `/Users/<user>/.docker/run/docker.sock`,
  which no longer exists. `sudo podman-mac-helper install` followed by a machine
  restart repoints it at the machine's API socket, which is what lets Docker API
  clients (testcontainers, IDE plugins, compose) work without `DOCKER_HOST`.
- `/usr/local/bin/docker` is a dangling symlink into the removed `Docker.app`, so
  there is no working `docker` CLI on the host. `brew install docker` installs the
  client alone.

Without the helper, clients that honour `DOCKER_HOST` still work:
`export DOCKER_HOST='unix://<machine api.sock>'` (deploy.sh prints the path).

### 3. Rootless vs rootful - a decision, not a bug

The machine runs rootless, which is the safer default and the reason SentinelOne
sees containers under the user slice. Docker's daemon is rootful, so some
Docker-compatible workloads (ports below 1024, some volume permission
expectations) behave differently. `podman machine set --rootful` switches it; if
that is ever done, `/run/docker.sock` has to be repointed at
`/run/podman/podman.sock`.

### 4. SSL certificate handling

**Impact**: enterprise users with private registries

Copy host certificates into the VM for private registry access:
- source: host certificate store via virtiofs
- destination: `/etc/containers/certs.d/`

### 5. Machine inspection endpoint

Report machine configuration, resource usage and installed packages for
`podman machine inspect` compatibility.

## Known unknowns

- SentinelOne's scanner logs 63 `scanner error 1` entries, 19 of them on files in
  container storage and the rest elsewhere - so not btrfs specific, but not
  explained either
- Podman 6 picks the vfkit REST port without checking availability. It collided
  with another local service once, and every `podman machine` command then failed
  with `unknown machine state:`. Workaround: edit `Endpoint` in
  `~/.config/containers/podman/machine/applehv/<name>.json` to a free port.

## Resolved

- **btrfs conversion produced an unbootable image.** The GRUB rewrite used
  guestfish `sh "if [ -f ... ]; then sed ...; fi"`, which silently did nothing, so
  the EFI stub kept searching for the old ext4 UUID and GRUB dropped into the
  rescue prompt while the build reported success. Now rewritten deterministically
  and verified with `virt-cat`.
- **Packages silently missing from the image.** `dpkg -i` left packages
  unconfigured, `apt-get install -f` removed them, and only seven packages were
  ever verified - the image lost crun, chrony, cifs-utils and nfs-common, and
  podman ran containers on runc while containers.conf asked for crun.
- **Podman 6 hiding `/etc/containers`.** Its `etc-containers.mount` bind mounts
  the host's `~/.config/containers` over the directory, which hid `storage.conf`
  (driver fell back to overlay), `containers.conf` (runtime, netns, dns ignored),
  `policy.json` (no image could be pulled at all) and `podman-machine` (podman
  stopped recognising it runs in a machine, so no published port was ever
  forwarded to the host). The Ignition provider now skips that unit.
- **`podman logs` returned nothing.** The machine user was not in
  `systemd-journal`, so reading back journald-driven container logs produced
  silence, and anything waiting on a log line hung - kind failed with "could not
  find a log line that matches Reached target Multi-User System". The group was
  in fact being granted; the fault was ordering. logind had already started
  `user@501.service` for the lingering user, and a process keeps the supplementary
  groups it started with, so the rootless podman service inside that manager
  stayed blind for the rest of the boot - while a fresh ssh login could read the
  journal perfectly well, which is what made it look fixed. `post-ignition-setup`
  now runs before user sessions are permitted, and restarts the manager if one
  got there first.
- **gvforwarder.** Previously listed as a possible fix for port forwarding. It is
  not needed: the guest-side agent that calls gvproxy's
  `/services/forwarder/expose` is podman itself, and it only does so when it
  recognises the machine marker. Fixing the marker fixed forwarding.
- **Timezone support.** Handled - Ignition sets `/etc/localtime` and the provider
  applies it.
- **Nothing enabled `podman.socket` if Ignition did not.** That socket is what
  the podman client on the Mac connects to, so losing it loses the machine
  entirely. `post-ignition-setup` now writes the wants symlink itself when
  neither location Ignition uses has one. Not with `systemctl --user`, as first
  sketched: the script runs as root, where `--user` has no user manager to talk
  to, and the unit is ordered before user sessions so the manager may not exist
  yet - and waiting on a systemd job from inside that unit is what deadlocked it
  against sshd once already. The symlink is exactly what `enable` writes and
  needs nothing running.
- **`podman machine init --playbook` did nothing.** The image now carries
  `ansible-core`, but installing it was the smaller half. Podman writes
  `playbook.service` for Fedora CoreOS and gates it on `ConditionFirstBoot=yes`,
  which is never true in this image: the build ships `/etc/machine-id` empty and
  systemd still does not call the result a first boot - on a real first boot
  `systemd-firstboot`, `first-boot-complete.target` and `sshd-keygen` were all
  skipped for that reason. Applied unchanged the playbook would have been skipped
  on every boot for ever, silently. The provider swaps the condition for a marker
  file and has the unit create it, so "only once" survives. `After=ready.service`
  is left alone - podman puts that unit in the same config and it is real here.
- **A share could be mounted over a system directory.** Wanted as a build time
  warning; it belongs where the mounts are actually created, in the Ignition
  provider, and refusing beats warning - a rejected share is recoverable, a
  machine whose `/usr` is gone is not. The match is exact rather than by prefix,
  because podman's own default shares include `/var/folders` and a prefix rule on
  `/var` would reject a stock machine. This generalises the hard-coded
  `etc-containers.mount` exception that was already there for the same reason.
- **No way to ask a stuck machine how it was doing.** Wanted as a vsock endpoint;
  that turned out to be impossible, not merely awkward. Podman gives the VM one
  vsock device, port 1025, and the unix socket behind it exists only while
  `podman machine start` waits for the ready signal - afterwards there is nothing
  on the host to connect to, and vfkit's arguments are podman's to choose.
  `podman-machine-health` therefore reports over the serial console, which vfkit
  captures to a file on the Mac and which keeps working when ssh, the network and
  podman are gone. Note that `/dev/console` is `tty0` in this guest and is not
  that port, so `StandardOutput=console` reaches nobody; it has to be
  `/dev/hvc0`. One line at the end of boot, then on change or a heartbeat, so an
  idle machine does not grow the host's log.
- **Nothing to look at when a machine came up wrong.** Every failure above is
  silent: the machine boots, podman answers, and only some later operation
  behaves strangely. `podman-machine-diagnostics` now runs at the end of every
  boot - after the ready signal, so `podman machine start` does not pay for it -
  and asks about each of them by name, marking anything it cannot vouch for as
  `FAULT` with the consequence spelled out. It can also be run by hand at any
  time, and `podman-machine-ready` now records how long each boot phase took and
  whether the vsock ready signal actually went out.

## Not Planned

### USB passthrough
Only available with the QEMU provider; AppleHV does not support it.

### Zincati auto-updates
A Fedora CoreOS feature, not applicable to a Debian base. Rebuild instead.

## References

- [Podman Machine Documentation](https://docs.podman.io/en/latest/markdown/podman-machine.1.html)
- [Ignition Specification v3.5](https://coreos.github.io/ignition/configuration-v3_5/)
- [vfkit Documentation](https://github.com/crc-org/vfkit)
- [gvisor-tap-vsock (gvproxy)](https://github.com/containers/gvisor-tap-vsock)
- [Podman AppleHV Issues](https://github.com/containers/podman/issues?q=applehv)
