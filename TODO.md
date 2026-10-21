# TODO - Future Improvements

Last reviewed: 2026-10-21

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

## In progress: repair customer volume migration

Reviewed 2026-10-21. The API diagnosis below is correct, but a custom Podman
package and signed repository must not delay recovery of existing backups.
The immediate fix keeps trixie's container stack and transfers volumes through
SSH. Packaging remains a separate, deferred project below.

### Evidence and corrections to the original plan

- Compared upstream `pkg/api/server/register_volumes.go` at
  [v5.4.2](https://github.com/containers/podman/blob/v5.4.2/pkg/api/server/register_volumes.go)
  and [v5.6.1](https://github.com/containers/podman/blob/v5.6.1/pkg/api/server/register_volumes.go).
  The former has no volume import/export routes; the latter registers both.
  This is an API capability gap, not a JSON or archive filename defect.
- The locally running guest reports `podman version 5.4.2` (checked 2026-10-21).
  The customer's exact server version and current Jamf scripts still need
  collecting; their supplied log reports only the host CLI version.
- An older server does not necessarily fail every client command. Conversely,
  `server minor >= client minor` is not a compatibility guarantee. Validate a
  concrete client/server pair and the operations the fleet uses.
- `deploy.sh` already avoids the missing REST endpoint, but was **not safe on
  import failure**: it logged the error and verified only volume existence, then
  could delete the backup. An empty volume could therefore count as restored.
- Do not infer the anonymous volume's owner from its name. Keep its name,
  driver, labels and options from inspect metadata; do not invent missing ones.
- Do not pass a customer's legacy backup directly to `deploy.sh --restore`.
  That command requires this project's manifest and layout. Use the volume
  transfer helper to recover a legacy volume archive, then the customer's
  container reconstruction procedure after validating the data.

### Delivery order

1. **Immediate recovery and Jamf integration**
   - [x] Provide `scripts/podman-volume-transfer.sh`: select an explicit machine,
     auto-detect its store or override rootful/rootless, stream through SSH,
     require an existing volume, validate tar structure, preserve a previous
     export on failure, and propagate nonzero status.
   - [x] Document running as the machine owner, creating volumes with original
     metadata, stopping writers, retaining backups, and checking recovered data.
   - [ ] Apply the helper to the customer's actual scripts (not present here)
     and test their October 9 archive on a test machine before fleet rollout.
2. **Prevent false success and backup loss in this repo**
   - [x] Preflight required lists and volume archives before a restore.
   - [x] Fail on image load, volume creation/import, reconstruction, start or SSH
     failure; require an explicit completion marker and successful verification.
   - [x] Keep the backup on failure; do not start restored applications after a
     volume import failure. A failed inventory cannot verify an empty backup.
   - [x] Add regression tests for missing archives, failed import/create,
     interrupted SSH, and the host's backup deletion gate.
   - [x] Record the live rootless/rootful round-trip results below.
3. **Release validation**
   - [ ] Run the complete machine-replacement migration on a disposable machine
     in a maintenance window; it stops the current VM, so do not run it alongside
     a build. Test interrupted restores too, retaining the backup.
   - [ ] Verify SentinelOne connectivity and health in the console separately;
     the customer's `Initializing` / `Connectivity Off` output proves neither.
4. **Optional server upgrade**
   - Revisit the packaging project only for a demonstrated requirement for the
     remote API/new features, or a security/lifecycle requirement. Choose a
     maintained release after assessing updates and the fleet's CLI version;
     5.6.1 below is the original reproduction target, not an evergreen release.
   - Keep Debian origin gates, package signing, dependency isolation, rollback
     and the client/server test matrix from the original plan. Explicitly test
     API capabilities rather than treating version ordering as proof.

### Verification results

Checked 2026-10-21:

- `./tests/run.sh unit`: 70 Python tests, 160 resource assertions and 57 deploy
  assertions passed. The 14 new Python tests cover restore and transfer failures.
- `./tests/integration/test_volume_transfer.sh`: **22 checks passed** on macOS
  client **6.1.4** / Debian guest **5.4.2**, rootless and rootful. Real binary data,
  ownership, permissions and symlink survived the helper round trip; the guest
  restore and the complete `deploy.sh --restore --keep-backup` entry point passed.
- The original VM remained running and no `s1-test-transfer-*` volumes remained
  in either store after cleanup. No workload or machine was stopped.
- New shell scripts pass ShellCheck at warning severity. `deploy.sh` retains
  existing ShellCheck warnings outside the changed restore code.
- The customer's client **5.6.1**, real archive, Jamf execution and SentinelOne
  console state remain unverified. Full replacement migration was not run: it
  would stop the active VM. This is a tested repository hotfix, not proof of
  customer deployment or a new image release.

## Remaining priorities after the migration hotfix

Review of the remaining TODO and implementation on 2026-10-21:

1. **Before customer rollout:** test the real Jamf policies, client 5.6.1 and
   saved archive, then run the complete disposable-machine migration. The
   isolated-volume tests above do not replace those acceptance checks.
2. **Next code fix: propagate SentinelOne deployment failures.** In
   `deploy_sentinelone()`, token registration failure only prints a warning;
   service enable/start failure is ignored, and an inactive service only prints
   another warning. Neither sets `S1_STATUS=1`. Consequently deployment can exit
   zero without a running/registered agent. Preserve the data-restore path, but
   return a failed deployment status for failed requested registration or service
   startup. Test these paths without a real token. Keep installation, service
   activity, agent health and management connectivity as separate outcomes;
   management connectivity can require initialization time and must not be
   inferred from `systemctl is-active`.
3. **Security acceptance:** confirm connectivity, health and actual container
   attribution in the SentinelOne console, rootless and rootful. Binary strings
   and provider log mentions are historical clues, not proof of supported
   container discovery or its absence. The existing registration integration
   test skips disconnected agents; a green suite alone does not close this.
4. **Revalidate historical host/agent issues before changing machines:** the
   dangling Docker socket/CLI, scanner error counts and vfkit port collision
   below describe earlier observations. Check the affected host and current
   agent/CLI version first. Fix Docker client compatibility where required by
   actual workloads; retain rootless/rootful as a workload decision.
5. **Deferred:** custom Podman packaging, signed apt hosting and its release
   process. No additional blocker for the SSH-based migration hotfix is proven
   by those open design questions. USB and Zincati remain out of scope.

## Deferred: ship our own podman, matched to the client

Status: **deferred; not implemented.** Original proposal dated 2026-10-14. Whoever
picks this up works through the phases in order; each phase ends with checks
that must pass before the next one starts. Record results in this section as
you go - numbers, versions, what failed and why - not only "done".

### Why

A customer's migration failed on restore:

```
[PodmanRestore] Importing volume: b01129e9...
Error: unmarshalling error into &errorhandling.ErrorModel{...}, data "Not Found\n": invalid character 'N' looking for beginning of value
```

Their Jamf scripts run `podman volume import` / `podman volume export` from the
Mac, i.e. through the remote API. The client on their Macs is podman **5.6.1**
(`/opt/podman/bin/podman`, the official pkg, deployed by Jamf). The image ships
trixie's podman **5.4.2**, whose API has no volume import/export endpoint; the
router answers a bare `Not Found`, which the client then fails to parse. The
successful backup is consistent with a previous server that supported these
endpoints, but the supplied log does not establish its version. The original
investigation recorded this reproduction on 2026-10-14 against a 5.4.2 machine:

```
podman volume create x && podman volume import x some.tar   # Error: Not Found
podman volume export x -o out.tar                           # Error: Not Found
```

The vendored upstream test says the same: `160-volumes.bats` has
`skip_if_remote "volumes import is not applicable on podman-remote"` at v5.4.2.

`deploy.sh` avoids this API error by running export/import inside the guest
over SSH. Its separate false-success bug is addressed in the immediate plan above.

The underlying problem is client/server skew. In a managed fleet the customer
controls the client version, so the server can be kept at the same minor. That
is what upstream machine-os does, and what this plan does with our own builds.

### What we give up, and accept

trixie-security stops covering podman. The stack came from trixie precisely for
that (see `docs/architecture.md`, "Kernel and container stack", and commit
`19112c9`). From now on **we** are the ones who ship podman's security fixes:
upstream fixes only its latest minor, so following upstream releases promptly
*is* the security process. Phase 5 defines it. If that process cannot be staffed,
stop and go back to trixie's podman - do not ship builds nobody updates.

### Version policy

- Track **containers/podman** releases (<https://github.com/containers/podman/releases>),
  not Podman Desktop. Podman Desktop has its own cadence and only bundles a podman
  installer. What matters is the podman CLI that Jamf puts on the Macs.
- Support explicitly tested client/server pairs. Matching the customer's minor
  is a useful starting point, but a newer server alone does not prove compatibility.
  Coordinate client changes with the fleet owner (open question 1).
- Patch releases of the current minor are taken as they come; ones with a CVE
  fix are taken urgently (phase 5).

### Phase 0 - spike: can we build podman 5.6.1 for trixie, and what does it cost?

Goal: an answer with numbers, before anything is committed to. Time box: two
days. Do the work on a branch; nothing here goes to `main` until phase 3.

Steps:

1. Decide the build approach by trying both, in a `debian:trixie` arm64
   container (podman inside the machine is fine):
   - **A. Backport Debian's packaging.** Take the podman source package from
     Debian (salsa.debian.org/debian/libpod, or sid) at the version closest to
     5.6.1 and rebuild it on trixie (`backportpackage`, or `sbuild` /
     `dpkg-buildpackage`). Debian's source is repacked (`+ds1`) and is likely
     built against Debian-packaged Go libraries (`golang-github-containers-*`)
     rather than upstream's `vendor/` - **verify this**; if so, those libraries
     have to be backported too, and count them.
   - **B. Upstream tarball with its own `vendor/`.** Build the upstream v5.6.1
     release with upstream's vendored modules and a minimal `debian/` of our
     own. Fewer moving parts; diverges from Debian's file layout, so compare
     with `dpkg -L podman` from trixie and keep the same paths (binaries in
     `/usr/bin`, systemd units in `/usr/lib/systemd/{system,user}`,
     `/usr/libexec/podman/*`, man pages optional).
2. Go toolchain: read the `go` directive in podman's `go.mod` at the tag and
   compare with trixie's `golang-go`. If trixie's is too old, use the official
   Go tarball for the build only, verified against its published sha256. The
   toolchain must not end up in the image.
3. Runtime dependencies: from podman's release notes and `go.mod` / docs at the
   tag, find the minimum versions of crun, conmon, netavark, aardvark-dns,
   passt and containers-common that 5.6.1 expects. Compare with trixie (crun
   1.21, conmon 2.1.12, netavark and aardvark-dns 1.14) and backports (passt).
   Rebuild only what is actually required; prefer keeping trixie's.
4. Check what the build pulls: `apt-get install --simulate` of the resulting
   `.deb`s on a clean `debian:trixie`. The count of packages that are not from
   trixie must be the ones we built and nothing else - no libc6, systemd or
   OpenSSL from anywhere else (that is what ended the unstable experiment).
5. Install the result into a throwaway machine without rebuilding the image:
   `GUEST_PATCH` (see `tests/podman-system/VENDORED.md`, "Trying a fix without
   rebuilding") with a script that `dpkg -i`s the debs and restarts
   `podman.socket` for core and root.

Checks - all must hold to call the spike a success:

- [ ] `podman version` from the Mac shows Server `5.6.1`
- [ ] from the Mac, over the remote API, against that machine:
      `podman volume create v && podman volume import v t.tar && podman volume export v -o o.tar`
      succeeds and `o.tar` contains what `t.tar` did
- [ ] `apt-get install --simulate` on clean trixie pulls nothing but our debs and
      trixie packages (list them here)
- [ ] the vendored suite synced to v5.6.1 (`PODMAN_VERSION=v5.6.1 ./tests/podman-system/sync.sh`)
      runs in a throwaway machine; compare with the 5.4.2 baseline in
      `tests/podman-system/VENDORED.md` (583 ok / 34 failed / 79 skipped).
      Every failure that is not in the baseline's categories is characterised
      before going on
- [ ] the migration layer passes: `./tests/run.sh migration`

Write down here: approach chosen (A or B) and why, Go version used, which
packages had to be rebuilt, the dependency simulation output, suite numbers,
and an estimate of the effort for each later release. **Then stop and let the
owner decide whether to continue** (decision point after phase 0).

### Phase 1 - reproducible build

1. Put the packaging in this repo (`packaging/podman/` or similar), with a
   script that builds the debs from a version argument:
   `./packaging/build-podman.sh v5.6.1` -> `.deb`s in `output/debs/`.
2. Version string that sorts above trixie's and says where it comes from, e.g.
   `5.6.1+ds1-0s1~trixie1` (pick the form that fits the approach; it must sort
   above any `5.4.2+ds1-*+deb13uN` trixie-security may publish - check with
   `dpkg --compare-versions`).
3. Build runs in a `debian:trixie` container, arm64 (x86_64 too if `ARCH=x86_64`
   images are still built), with every input pinned: podman tag, Go tarball
   sha256, base image digest.

Checks:

- [ ] two builds from a clean checkout produce debs with the same content
      (`diffoscope` or at least `dpkg-deb -c` + binary sha256 compared)
- [ ] `dpkg --compare-versions <ours> gt <trixie's>` holds, and also against a
      hypothetical `5.4.2+ds1-2+deb13u9`
- [ ] `podman version` of the installed package reports the expected version
      and Go version

### Phase 2 - signed apt repository

1. A GPG signing key for the repo. Where the private key lives and who can sign
   is open question 2 - do not generate a key that ends up in this repo.
2. A plain apt repository (`reprepro` or `aptly`), suite name e.g.
   `trixie-s1`. The name must not contain `sid`, `unstable`, `testing` or
   `forky`: `install.sh` refuses those sources by regex.
3. Hosting is open question 3 (customer's Artifactory can host Debian repos and
   is reachable through their Zscaler; a public URL is the alternative). Every
   machine must reach it, through Zscaler.

Checks:

- [ ] `apt-get update` in a clean `debian:trixie` with the repo configured via
      `signed-by=` succeeds; with a wrong key it fails
- [ ] `apt-cache policy podman` shows our version as candidate, from our repo
- [ ] a tampered `Release` file is rejected

### Phase 3 - image integration

Files that have to change (read each one before changing it; the comments
explain why things are the way they are):

- `build.sh` - `PACKAGES` stays the single list. Add a switch, e.g.
  `PODMAN_SOURCE=trixie|s1` (default `s1` once phase 4 passes), so an image
  with trixie's podman can still be built as a fallback.
- `resources/install.sh`
  - install the repo key to `/usr/share/keyrings/`, the source to
    `/etc/apt/sources.list.d/` with `signed-by=`, **kept in the image** so
    machines receive updates through `apt-get upgrade` (same reasoning as
    backports, see the comment at "Enabling trixie-backports")
  - an apt preferences file pinning **only** our packages to our origin (by
    `Origin`/`Label` of our `Release`), so trixie never replaces them and our
    repo never replaces anything else
  - the origin gate (`Verifying package origins`): today it fails on any
    `,local]` package. Our packages come from a configured source so they are
    not `local` - but add an explicit check that the podman stack's installed
    version comes from our origin when `PODMAN_SOURCE=s1`, and from trixie
    when `trixie`
  - the version printout under `=== Container stack ===` and its comment
- `resources/configs/storage.conf`, `resources/configs/storage-user.conf`,
  `resources/scripts/post-ignition-setup.sh` - the runroot/graphroot split was
  made for the difference between 5.4 and 5.8 (commit `ed2c44c`). Verify it
  still holds for the new version, rootless **and** rootful; keep it working
  for 5.4 too while `PODMAN_SOURCE=trixie` exists.
- `deploy.sh` - the `--no-pod-prefix` fallback (around line 595) stays for 5.4;
  verify the main path on the new version.
- `resources/scripts/ignition-provider.py` - `SKIPPED_UNITS` and its comment
  mention 5.4.2. `etc-containers.mount` must stay skipped regardless of version
  (the image's `/etc/containers` must not be hidden); fix only the wording.
- docs: `docs/README.md`, `docs/architecture.md` ("Kernel and container
  stack" table and text), `docs/build.md` ("Rebuilding when Debian moves" and
  the gates list), `docs/troubleshooting.md` (5.4 sections), `docs/testing.md`,
  `tests/podman-system/VENDORED.md` (new baseline)
- `tests/podman-system/sync.sh` default `PODMAN_VERSION`, and re-sync `vendor/`

Checks:

- [ ] `make build` succeeds with `PODMAN_SOURCE=s1` and with `PODMAN_SOURCE=trixie`
- [ ] in the s1 image: `apt-cache policy podman crun conmon netavark aardvark-dns`
      shows each from the intended origin; `apt list --installed | grep ',local]'`
      shows only `sentinelagent`
- [ ] `./tests/run.sh image` passes
- [ ] a simulated trixie-security podman update does not replace ours
      (`apt-get -s upgrade` after adding a fake higher-than-5.4.2 trixie version
      is the cheapest way to show it)

### Phase 4 - full verification

Run on the s1 image, in this order, and record the numbers here:

- [ ] `./tests/run.sh` (unit, image, integration) - all green
- [ ] `./tests/run.sh machine` - lifecycle
- [ ] `./tests/run.sh migration` - data across a replacement, **and** the same
      scenario done the customer's way: export and import volumes from the
      Mac over the remote API. Add this as a test (in
      `tests/machine/test_migration.sh` or a new integration test) so a server
      without the endpoint fails loudly next time
- [ ] `./tests/run.sh podman-system` rootless and `PODMAN_SYSTEM_ROOTFUL=1`;
      new baseline written into `VENDORED.md` in the same form as the current one
- [ ] client/server matrix from the Mac, at least: client 5.6.x (customer's),
      client 6.x (current brew). `podman info`, run, logs, exec, build, volume
      import/export, `kube play`, published port reachable from macOS
- [ ] SentinelOne agent installs and runs on the new image (the customer's
      script 2 output is the reference: agent state `Enabled`, health
      eventually not `Initializing`)
- [ ] `podman-machine-diagnostics` in the guest reports no `FAULT`

### Phase 5 - release and security process

1. **Watch:** podman GitHub releases and security advisories
   (<https://github.com/containers/podman/security/advisories>), Go security
   releases (a Go CVE means a rebuild even with no podman release), and the
   Debian security tracker for podman/crun/conmon/netavark as an extra signal.
   Automate the notification (a scheduled CI job or GitHub's release watch);
   a human must get it.
2. **Per release:** build (phase 1 script) -> sync vendored suite -> run phase 4
   checks that are automatable -> publish to the repo -> machines get it via
   `apt-get upgrade`. A new image is only needed when something outside the
   packages changes.
3. **Targets** (open question 4, proposal): security fix published to our repo
   within 2 working days of upstream; non-security patch releases batched.
4. **Rollback:** the repo keeps the previous version; document
   `apt-get install podman=<previous>` in `docs/troubleshooting.md`.
5. There is no CI in this repo today. Decide where builds run (open question 5).

Checks:

- [ ] a dry run of the whole loop for one patch release, timed
- [ ] the rollback command was actually run once on a test machine

### Independent, do now: fix the customer's scripts

Implemented as `scripts/podman-volume-transfer.sh`; see
[the recovery procedure](docs/troubleshooting.md#volume-restore-fails-with-not-found).
Servers without these API endpoints need SSH transfer. The low-level equivalents
below require explicitly naming the machine and choosing the correct store:

```sh
podman machine ssh podman-machine-default "podman volume create $v"
podman machine ssh podman-machine-default "podman volume import $v -" < "$DIR/volumes/$v.tar"
podman machine ssh podman-machine-default "podman volume export $v" > "$DIR/volumes/$v.tar"
```

Verified on 2026-10-14 against a 5.4.2 machine. The volume must exist before
import. The failing volume (`b01129e9...`) has an anonymous-style name; its owner is
unverified. Recreating it with a bare `volume create` loses its labels and
options - `deploy.sh` regenerates them from `volume inspect`
(`volumes-create.sh`), and the scripts should do the same. For future migrations,
use `deploy.sh --preserve` / `--restore` with backups created by `deploy.sh`.

### Open questions for the owner

1. Will the customer agree to move their Jamf podman client only after we ship
   the matching server?
2. Where does the repo signing key live, and who may sign?
3. Where is the apt repo hosted (customer's Artifactory, or ours)?
4. Who owns the security watch, and what response time do we commit to?
5. Where do the package builds run - no CI exists yet.

### Working rules for this task

- Destructive test layers (`machine`, `migration`, `podman-system`) create
  throwaway machines named `s1-test*` and stop the running ones; they restore
  the previously running set afterwards (`machine_stash_running` /
  `machine_restore_running` in `tests/lib/machine.sh`). Check that the user's
  machines are running again after a run.
- An image build takes about 50 minutes and must not be interrupted; see
  `docs/build.md`. Nothing may stop the machine the build runs in.
- Commit messages: plain, in the style of `git log`; no `Co-Authored-By` or
  other AI attribution lines.

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
- **A machine inspection endpoint - dropped, the premise was wrong.** It was
  written as reporting configuration, resource usage and installed packages "for
  `podman machine inspect` compatibility". That command never asks the guest
  anything: every field it prints comes from podman's own config file on the Mac,
  and `.Resources.*` is the allocation the machine was given, not what it uses.
  The proof came for free while chasing the boot deadlock - with the guest
  completely unreachable, sshd not listening and gvproxy dead,
  `podman machine inspect --format '{{.AppleHypervisor.Vfkit.Endpoint}}'` still
  answered normally. There is no hook for a guest to contribute fields, so
  nothing built here could ever have reached it. What configuration is worth
  checking is already covered by `podman-machine-diagnostics`; usage and package
  lists had no consumer once the compatibility claim fell away.
- **TLS inspection broke everything and `--import-native-ca` did not help.**
  Recorded as private-registry certificates and `certs.d`; the real case is a
  network that re-signs TLS with a corporate CA, which breaks pulls, apt in the
  guest and the agent alike. Podman already has `--import-native-ca` for it, but
  it is hard-coded for Fedora CoreOS: it copies into
  `/etc/pki/ca-trust/source/anchors` and runs `sudo update-ca-trust`, neither of
  which exists on Debian, so the flag imported nothing. The image now provides
  both under those names, mapped onto `update-ca-certificates`. Two details
  decided whether it actually worked: Debian only reads `*.crt` while podman
  writes `host-ca-certs.pem`, and `openssl rehash` skips any file holding more
  than one certificate - so the concatenated bundle had to be split, or the CAs
  would have been trusted by CAfile and refused by CApath. Containers still do
  not inherit any of it, and the agent needs excluding from inspection rather
  than trusting the CA; both are written up in
  [docs/troubleshooting.md](docs/troubleshooting.md).
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
