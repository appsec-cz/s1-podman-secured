# Tests

Five layers, ordered by what they cost to run. The cheap ones run in seconds and
catch the mistakes that are cheap to make; the expensive ones boot a real machine
and catch the ones that only appear when everything is assembled.

```
./tests/run.sh                 # unit + image + integration  (~2 min, safe)
./tests/run.sh all             # everything                  (~1 h, destructive)
./tests/run.sh unit image      # pick layers
```

| Layer | Runs where | Needs | Time | Destructive |
|---|---|---|---|---|
| `unit` | macOS | python3 | 1 s | no |
| `image` | macOS | python3, zstd | 30 s | no |
| `integration` | against a running machine | a machine | 2 min | no |
| `machine` | throwaway machine | the built image | 10 min | **yes** |
| `podman-system` | throwaway machine | the built image | 30-60 min | **yes** |

## Why the layers are cut this way

Each layer answers a different question, and they are ordered so the cheapest
question that can fail is asked first.

**unit — is the repository self consistent?** Scripts parse, the provider
compiles, configs are valid TOML, every file `build.sh` requires exists, every
`ExecStart` points at something `install.sh` installs. It also asserts a handful
of specific things that were broken before: that `storage.conf` selects btrfs,
that both container configs are written where podman 6 cannot shadow them, that
the Ignition provider skips `etc-containers.mount`, that `post-ignition-setup`
grants journal access and installs a policy fallback, and that `build.sh` still
verifies the bootloader after conversion. Those assertions exist so a fix cannot
be quietly reverted.

Plus 31 python unit tests for `ignition-provider.py` - hostname extraction
including base64, file, directory and link creation, and config dispatch. The
provider is the most intricate piece in the project and the only one with real
logic; the rest is configuration.

**image — did the build produce something that can boot?** Reads the GPT, finds
the partitions, checks the root filesystem is btrfs and no ext4 is left, and
verifies that the GRUB stub on the EFI partition searches for *the UUID the
filesystem actually has*. That single check is the layer's reason to exist: a
mismatch there produces an image that builds "successfully" and then sits at a
GRUB rescue prompt with an empty console, which costs an afternoon to diagnose
from the outside. It needs no VM and no libguestfs - just the first 220 MB of the
image.

**integration — does the configuration take effect?** Writing a config file into
an image is not the same as podman using it. This layer asks the running guest
what it actually does: which storage driver, which OCI runtime, whether the
machine marker is visible, whether the packages the build intended are really
installed, whether the user can read the journal. Then it exercises behaviour -
a container runs, its layers are btrfs subvolumes, `podman logs` returns output,
a published port reaches macOS, containers resolve each other by name, the Docker
API socket answers on both sides, `podman kube play` works. It creates and
removes only its own containers, so it is safe to point at a machine in use.

**machine — does a fresh machine come up?** Creates a throwaway machine from the
built image and walks the lifecycle: init, start, ssh, Ignition completion,
post-Ignition setup, resources matching the request, host directories mounted,
the ready signal, stop, start again, no failed units, remove. This is what
catches an image that builds and boots but never finishes provisioning, where
`podman machine start` simply hangs.

**podman-system — does podman itself still behave on this configuration?** See
[podman-system/VENDORED.md](podman-system/VENDORED.md). Podman's own bats suite,
pinned to the podman version inside the image, run in a throwaway machine.

## Safety

The last two layers are destructive: `machine` deletes machines, and podman's
system suite wipes container storage - upstream says so in bold. Both refuse to
run against a machine whose name does not start with `s1-test`:

```
ERROR: refusing to use machine 'podman-machine-default'.
```

Override with `ALLOW_UNSAFE_MACHINE=1` only if you mean it. They also stop the
machine that was running before (only one can run at a time) and start it again
afterwards.

## Running pieces

```bash
./tests/run.sh integration                     # against whatever machine is running
TEST_MACHINE_EXPLICIT=my-machine ./tests/run.sh integration
TEST_FILTER=port ./tests/integration/test_runtime_behaviour.sh
RUN_KIND=1 ./tests/integration/test_kubernetes.sh   # opt-in, pulls ~1 GB
KEEP_MACHINE=1 ./tests/run.sh machine          # leave the machine for poking at
./tests/podman-system/run.sh 500 035           # only networking and logs
```

`TEST_IMAGE_PATH` points the image and machine layers at a specific build;
by default they take the newest `output/podman-debian*.raw.zst`.

## Writing a test

Source `lib/common.sh`, write functions named `test_*`, call `run_tests` at the
end. Assertions take their description last so failures read as sentences:

```bash
assert_eq "btrfs" "$driver" "rootless podman uses the btrfs driver"
```

`run_tests` calls test functions in alphabetical order, so nothing may depend on
another test having run first; do setup at file scope or inside the test. For
anything that touches a guest, `lib/machine.sh` provides `guest`, `guest_script`
(a script over stdin, which avoids nesting quotes through ssh and podman), and
the throwaway machine helpers.

When you fix a bug, add the assertion that would have caught it and say so in a
comment. Most of the assertions here are written that way, which is why they read
like a list of past failures - because they are.

## Known gaps

- The `machine` and `podman-system` layers have not been run end to end in CI;
  they are written against the same machine APIs the other layers use, but budget
  time the first time.
- Whether SentinelOne attributes container context to podman workloads cannot be
  tested from here. `integration/test_sentinelone.sh` checks what the image is
  responsible for and reports the agent's own status; the rest needs a registered
  agent and the console.
- Nothing tests the build itself end to end - that needs a Linux host with
  libguestfs. The `image` layer checks the artifact instead, which is where the
  build's mistakes become visible anyway.
