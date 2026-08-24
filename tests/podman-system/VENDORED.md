# Vendored podman system tests

`vendor/` holds a copy of podman's own bats system test suite, pinned to the
podman version that ships inside the image. Run `./sync.sh` to refresh it (set
`PODMAN_VERSION` first when Debian's podman moves).

- Upstream: <https://github.com/containers/podman>, `test/system/`
- Licence: Apache-2.0, see `vendor/LICENSE`
- Pinned version: see `vendor/.podman-version`

## Why vendor podman's tests at all

Debian already tests that podman works. What Debian does not test is podman
*configured the way this image configures it*: a btrfs graph driver, crun as the
runtime, netavark and aardvark-dns, journald log driver read back by a rootless
user, subuid ranges assigned by Ignition, cgroup delegation through
`user@.service`. Every one of those has broken here at least once, and each time
the symptom appeared somewhere far from the cause.

Podman's suite hits that surface far harder than anything hand written, and it
speaks the same language as the podman in the image, so a failure points at our
configuration rather than at the test.

## What was taken and what was left

Taken: the parts that exercise something this image is responsible for -
image and container lifecycle, logs, exec, mounts, volumes, namespaces and
userns, pods, healthchecks, systemd integration and socket activation, cgroups,
networking including pasta, kube play, containers.conf handling, compose, and
the format and CLI parsing checks that are cheap to run.

Left out, with reasons:

| Test | Why not |
|---|---|
| `410-selinux.bats` | Debian has no SELinux |
| `520-checkpoint.bats` | needs CRIU, not installed |
| `150-login.bats`, `155-partial-pull.bats`, `255-auto-update.bats` | need a local registry with auth |
| `750-trust.bats` | needs a GPG trust setup |
| `180-blkio.bats` | needs blkio controller behaviour we do not configure |
| `012-manifest.bats`, `037-runlabel.bats`, `032-sig-proxy.bats` | marginal for a machine image |
| `330-corrupt-images.bats`, `331-system-check.bats`, `760-system-renumber.bats` | deliberately corrupt storage |
| `260-sdnotify.bats`, `900-ssh.bats`, `950-preexec-hooks.bats` | test podman features this image does not set up |

Adding one back is a line in `sync.sh`.

## Running it

```bash
./tests/podman-system/run.sh          # the whole vendored suite
./tests/podman-system/run.sh 500 035  # only 500-networking and 035-logs
PODMAN_SYSTEM_ROOTFUL=1 ./tests/podman-system/run.sh
```

The runner creates a throwaway machine from the built image, installs bats and
the tools the suite needs, copies `vendor/` in and runs it there. It refuses to
touch a machine whose name does not start with `s1-test`, because **the suite
wipes container storage** - upstream's own warning. Expect it to take a while:
the suite is thorough and the machine is created from scratch.

## Baseline: what this suite does on this image

Full run against the image built on 2026-08-24 - kernel 7.1.8 from backports,
podman 5.8.4 from unstable - rootless, in a throwaway machine:

```
630 passed, 34 failed, 82 skipped   (about 50 minutes)
```

For comparison, the same image with Debian stable's podman 5.4.2 scored
584 passed, 33 failed, 79 skipped: the newer podman brings a larger suite and
passes 46 more tests, with the same failures plus `[200] podman pod create -
hashtag AllTheOptions`, which comes and goes between runs.

Podman's own banner confirms what it is testing:

```
Arch:arm64 OS:debian13 Runtime:crun Rootless:true Events:journald
Logdriver:journald Cgroups:v2+systemd Net:netavark DB:sqlite Store:btrfs
```

The failures are not all defects. Compare a new run against this breakdown
rather than against zero.

**26 - published ports go through gvproxy (expected inside a machine).**
`505-networking-pasta` (19), `500-networking` (6), `030-run` (1). Upstream runs
these on a plain host where podman binds the port itself. Inside a machine podman
delegates to gvproxy, which answers differently: `proxy already running` instead
of `address already in use`, and `bind: can't assign requested address` when a
test publishes on the VM's own address, which only the host side could bind.
Podman's machine tests live elsewhere (`pkg/machine/e2e`) precisely because of
this. Not fixable from here, and nothing is actually broken - our own
`integration/test_runtime_behaviour.sh` checks that a published port does reach
macOS.

**5 - the storage driver and its neighbourhood.** `005-info` (3), `010-images` (1),
`550-pause-process` (1). Pinning `driver = "btrfs"` used to make every podman
invocation whose store is not on btrfs fail outright - and `/tmp` is tmpfs, so
anything using `--root` there died. `storage.conf` now sets
`driver_priority = ["btrfs", "overlay"]` instead, which fixed three of them.
`[005] podman info - json` appeared with podman 5.8.4 and has not been looked at.

The two that remain are not ours to fix: `[005] empty string defaults` sets its
own storage.conf and then cannot use any driver on tmpfs, and `[010] additional
store` fails in an upstream helper that only knows overlay and vfs
(*"Unknown storage driver 'btrfs'"*).

**1 - netavark cleanup race.** `[550] rootless reexec with sig-proxy when
rejoining userns`: *failed to delete container veth eth0: Netlink error: No such
device*. Seen once, in teardown. Worth watching rather than chasing.

**5 - not characterised yet.** `252-quadlet` (2), `600-completion` (2), and
`[200] podman pod create - hashtag AllTheOptions`. The pod one fails on
*"cannot set hostname when joining the pod UTS namespace"*, which reads like a
podman version and test expectation mismatch rather than a configuration
problem.

## Trying a fix without rebuilding

A rebuild takes about fifty minutes, which is a poor loop for "does this config
change help?". `GUEST_PATCH` points at a script that runs inside the fresh
machine before the suite starts:

```bash
GUEST_PATCH=/tmp/patch-storage.sh ./tests/podman-system/run.sh 005 010 550
```

That is how the `driver_priority` change above was verified: three failures
turned into passes before the change was committed, let alone built.

## Keeping it honest

`run.sh` compares the podman version in the guest with the pinned version and
warns when they drift. A suite from a different podman produces failures that
say more about the version gap than about the image.
