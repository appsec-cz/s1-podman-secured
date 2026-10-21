# Testing

The suite lives in [`tests/`](../tests/README.md), which documents each layer in
detail. This page is the short version: what to run, and when.

```bash
./tests/run.sh                 # unit + image + integration   ~2 min, safe
./tests/run.sh all             # everything                   ~1 h, destructive
```

| Layer | Answers | Time | Safe against a machine in use |
|---|---|---|---|
| `unit` | is the repository self consistent? | 1 s | yes |
| `image` | can the built image boot? | 30 s | yes |
| `integration` | does the configuration take effect? | 2 min | yes |
| `machine` | does a fresh machine come up? | 1 min | **no** |
| `podman-system` | does podman behave on this configuration? | ~50 min | **no** |

The last two create and delete machines, and podman's own suite wipes container
storage, so both refuse any machine whose name does not start with `s1-test`.

## When to run what

**After building an image**, before deploying it anywhere:

```bash
./tests/run.sh image
```

Seconds, no VM, and it catches the failure mode that costs the most time: an
image that builds cleanly and cannot boot.

**After deploying**, against the machine you just made:

```bash
./tests/run.sh integration
```

This is the layer that tells you the configuration is not just present but in
effect - btrfs really in use, Rosetta really translating, ports really reaching
macOS, `podman logs` really returning output.

**After touching backup or restore**, verify the data round trip:

For a quick volume-only check without replacing or stopping the running machine:

```bash
./tests/integration/test_volume_transfer.sh
```

This creates and removes only its own `s1-test-transfer-*` volumes, in rootless
and rootful stores. It tests the SSH helper and `deploy.sh`'s guest restore with
real binary data, permissions and a symlink. It is also part of `integration`.
Unit tests inject failed imports, missing archives and SSH disconnects and check
that the host cannot discard the backup on those paths.

The full machine replacement still needs the migration layer:

```bash
./tests/run.sh migration
```

Destructive, and the only thing that proves it: each half looks fine alone - a
backup that writes files, and a restore that reports success while the data it
was meant to bring back is not there.

**Before shipping an image to a fleet**, everything:

```bash
./tests/run.sh all
```

Budget an hour. Compare podman's own suite against the baseline recorded in
[`tests/podman-system/VENDORED.md`](../tests/podman-system/VENDORED.md) rather
than against zero - a couple of dozen of its failures are inherent to running
inside a machine, where published ports go through gvproxy.

## Changing configuration without rebuilding

A rebuild is about an hour, which is a poor loop for "does this setting help?".
The suite runner takes a script to apply inside the fresh machine first:

```bash
GUEST_PATCH=/tmp/try-something.sh ./tests/podman-system/run.sh 005 010
```

That is how the storage driver change was validated before it was committed.

## Keeping the vendored suite aligned

`tests/podman-system/vendor/` is podman's own bats suite, pinned to the podman
version inside the image. When the image's podman moves:

```bash
PODMAN_VERSION=v5.4.2 ./tests/podman-system/sync.sh
```

The runner compares the two versions and warns when they drift, because a suite
from a different podman produces failures that say more about the version gap
than about the image.
