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

## Keeping it honest

`run.sh` compares the podman version in the guest with the pinned version and
warns when they drift. A suite from a different podman produces failures that
say more about the version gap than about the image.
