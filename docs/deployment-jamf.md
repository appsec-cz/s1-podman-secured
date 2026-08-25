# Deployment with Jamf Pro

Rolling the machine out to a fleet means getting four things onto each Mac and
then running one script as the logged-in user:

| What | Where it comes from | Why |
|---|---|---|
| podman CLI | vendor installer package | drives the machine |
| Rosetta | `softwareupdate` | x86_64 containers |
| the image (~1.2 GB) | your distribution, see below | the VM itself |
| the SentinelOne agent `.deb` | your own licensed copy | **not** in the image |

The agent is licensed per endpoint and is not redistributable, so it is never
baked into an image. It travels separately, over the same Jamf channel, and is
installed into the machine when the machine is created.

## Why the script must run as the user

A podman machine belongs to a user, not to the Mac. Its disk, configuration and
ssh key live in `~/.local/share/containers` and `~/.config/containers`. Jamf runs
policy scripts as root, so every podman command has to be handed back to the
console user:

```bash
console_user=$(stat -f%Su /dev/console)
console_uid=$(id -u "$console_user")

as_user() {
    launchctl asuser "$console_uid" sudo -u "$console_user" "$@"
}

as_user /opt/homebrew/bin/podman machine list
```

Running `podman machine init` as root creates a machine root owns, which the user
cannot see. That is the single most common way this deployment goes wrong.

## Step 1 - prerequisites

One Jamf policy, scoped to the target Macs, ordered before everything else.

**podman.** Take the installer package from the podman release page
(`podman-installer-macos-arm64.pkg`), upload it to Jamf as a package and let the
policy install it. It puts `podman` in `/opt/podman/bin`. Homebrew works too but
is harder to keep uniform across a fleet.

**Rosetta**, as a script in the same policy:

```bash
#!/bin/bash
if /usr/bin/pgrep -q oahd; then
    echo "Rosetta already installed"
    exit 0
fi
/usr/sbin/softwareupdate --install-rosetta --agree-to-license
```

Without Rosetta the machine still works; x86_64 containers fall back to qemu
emulation, which is correct but far slower.

## Step 2 - getting the image onto the Mac

Both options end with the same layout, which is what the deploy script expects:

```
/Library/Application Support/PodmanMachine/
├── podman-debian.raw.zst
├── podman-debian.raw.zst.sha256
├── deploy.sh
└── SentinelAgent-<version>.deb        (step 3)
```

### Option A - ship it as a Jamf package

Simplest, and versioning comes free: the package version is the image version.

```bash
mkdir -p payload/Library/Application\ Support/PodmanMachine
cp output/podman-debian.raw.zst          payload/Library/Application\ Support/PodmanMachine/
cp output/podman-debian.raw.zst.sha256   payload/Library/Application\ Support/PodmanMachine/
cp deploy.sh                             payload/Library/Application\ Support/PodmanMachine/
chmod +x payload/Library/Application\ Support/PodmanMachine/deploy.sh

pkgbuild --root payload \
         --identifier cz.appsec.podmanmachine.image \
         --version 2026.08.25 \
         --install-location / \
         PodmanMachineImage-2026.08.25.pkg
```

Sign it with your Developer ID installer certificate if the fleet enforces that,
upload it to Jamf, and scope the installing policy to the same Macs.

The cost is bandwidth: every version is another 1.2 GB through the distribution
points, and Jamf keeps the package in its cache.

### Option B - download it from your own host

Better when the image changes often. Publish the image and its `.sha256` on an
internal HTTPS host or a bucket, and have a Jamf script fetch it:

```bash
#!/bin/bash
# Jamf parameters: $4 = base URL, $5 = expected version
set -euo pipefail

BASE_URL="${4:?base URL required}"
VERSION="${5:?version required}"
DEST="/Library/Application Support/PodmanMachine"
IMAGE="$DEST/podman-debian.raw.zst"

mkdir -p "$DEST"

# Skip the download when the file we already have is the one we want.
if [ -f "$DEST/.version" ] && [ "$(cat "$DEST/.version")" = "$VERSION" ] && [ -f "$IMAGE" ]; then
    echo "Image $VERSION already present"
    exit 0
fi

curl -fsSL --retry 3 -o "$IMAGE.part"        "$BASE_URL/$VERSION/podman-debian.raw.zst"
curl -fsSL --retry 3 -o "$IMAGE.sha256.part" "$BASE_URL/$VERSION/podman-debian.raw.zst.sha256"

expected=$(awk '{print $1}' "$IMAGE.sha256.part")
actual=$(shasum -a 256 "$IMAGE.part" | awk '{print $1}')
if [ "$expected" != "$actual" ]; then
    echo "ERROR: checksum mismatch, refusing the download" >&2
    rm -f "$IMAGE.part" "$IMAGE.sha256.part"
    exit 1
fi

mv "$IMAGE.part" "$IMAGE"
mv "$IMAGE.sha256.part" "$IMAGE.sha256"
printf '%s' "$VERSION" > "$DEST/.version"
echo "Image $VERSION downloaded and verified"
```

Verify the checksum before use either way. A truncated image produces a machine
that fails in confusing places rather than failing to start.

## Step 3 - getting the agent onto the Mac

The `.deb` is the Linux ARM64 agent for the VM, not the macOS agent the Mac
itself runs. Both can be deployed by Jamf; they are different packages.

Package it the same way as the image, into the same directory:

```bash
mkdir -p payload/Library/Application\ Support/PodmanMachine
cp SentinelAgent-aarch64_linux_aarch64_v25_4_1_24.deb \
   payload/Library/Application\ Support/PodmanMachine/

pkgbuild --root payload \
         --identifier cz.appsec.podmanmachine.s1agent \
         --version 25.4.1.24 \
         --install-location / \
         PodmanMachineS1Agent-25.4.1.24.pkg
```

Keep it to your own distribution channel and lock the file down - it is licensed
material:

```bash
chown root:wheel "/Library/Application Support/PodmanMachine/SentinelAgent-"*.deb
chmod 0640       "/Library/Application Support/PodmanMachine/SentinelAgent-"*.deb
```

Updating the agent is a new package plus a re-run of the deploy policy, or the
smaller in-place path in [step 6](#step-6---updating).

### The site token

Never in the image, never in a package. Pass it as a Jamf script parameter, so it
lives in the Jamf policy rather than on disk:

- Jamf policy → Scripts → the deploy script → **Parameter 4**: the site token

Script parameters are visible to Jamf administrators; if that is too broad, leave
the token out entirely and register the agents from the SentinelOne console
instead. The deploy script handles both - without a token the agent is installed
and started, just unregistered.

## Step 4 - the deployment policy

One script, `Parameter 4` = site token, `Parameter 5` = `replace` to allow
replacing an existing machine.

```bash
#!/bin/bash
# Deploy the Podman machine for the console user.
# $4 = SentinelOne site token (optional)
# $5 = "replace" to delete an existing machine first (destroys its contents)
set -uo pipefail

DIR="/Library/Application Support/PodmanMachine"
S1_TOKEN="${4:-}"
REPLACE="${5:-}"
PODMAN="/opt/podman/bin/podman"

console_user=$(stat -f%Su /dev/console)
if [ -z "$console_user" ] || [ "$console_user" = "root" ] || [ "$console_user" = "loginwindow" ]; then
    echo "No user logged in - deferring"
    exit 1        # Jamf will retry at the next check-in
fi
console_uid=$(id -u "$console_user")

as_user() { launchctl asuser "$console_uid" sudo -u "$console_user" "$@"; }

[ -x "$PODMAN" ] || { echo "ERROR: podman is not installed"; exit 1; }
[ -f "$DIR/podman-debian.raw.zst" ] || { echo "ERROR: no image in $DIR"; exit 1; }

# The machine belongs to the user, so the whole deployment runs as them.
if as_user "$PODMAN" machine inspect podman-machine-default >/dev/null 2>&1; then
    if [ "$REPLACE" != "replace" ]; then
        echo "Machine already exists; pass 'replace' to recreate it"
        exit 0
    fi
    echo "Replacing the existing machine"
    as_user "$PODMAN" machine stop podman-machine-default >/dev/null 2>&1
    as_user "$PODMAN" machine rm -f podman-machine-default >/dev/null 2>&1
fi

cd "$DIR" || exit 1
if [ -n "$S1_TOKEN" ]; then
    as_user /bin/bash ./deploy.sh --token "$S1_TOKEN"
else
    as_user /bin/bash ./deploy.sh
fi
```

`deploy.sh` picks up `podman-debian*.raw.zst` and `SentinelAgent*.deb` from the
working directory, which is why the script changes into `$DIR` first. It also
enables Rosetta in the user's `containers.conf`, creates and starts the machine,
sets the VM hostname to `<mac-hostname>-podman`, installs the agent and starts
it.

Expect the policy to take several minutes: the image is decompressed and copied,
and the machine boots and provisions itself.

### Scoping and triggers

- **Self Service** for a voluntary rollout - the user runs it when convenient,
  which matters because it can replace a machine they are using.
- **Recurring check-in** with a smart group of "podman installed and no machine
  present" for an unattended rollout.
- Deploying to a Mac with no one logged in cannot work; the script exits non-zero
  so Jamf retries later.

## Step 5 - verification

Extension attributes make the fleet state visible in Jamf. Each returns one line.

**Machine state:**

```bash
#!/bin/bash
console_user=$(stat -f%Su /dev/console)
[ -z "$console_user" ] || [ "$console_user" = "root" ] && { echo "<result>no user</result>"; exit 0; }
state=$(launchctl asuser "$(id -u "$console_user")" sudo -u "$console_user" \
        /opt/podman/bin/podman machine inspect podman-machine-default --format '{{.State}}' 2>/dev/null)
echo "<result>${state:-not deployed}</result>"
```

**Agent state inside the machine:**

```bash
#!/bin/bash
console_user=$(stat -f%Su /dev/console)
[ -z "$console_user" ] || [ "$console_user" = "root" ] && { echo "<result>no user</result>"; exit 0; }
as_user() { launchctl asuser "$(id -u "$console_user")" sudo -u "$console_user" "$@"; }
out=$(as_user /opt/podman/bin/podman machine ssh podman-machine-default \
      'systemctl is-active sentinelone' 2>/dev/null | tr -d '\r')
echo "<result>${out:-unreachable}</result>"
```

**Image version**, if you use the download route and write `.version`:

```bash
#!/bin/bash
v=$(cat "/Library/Application Support/PodmanMachine/.version" 2>/dev/null)
echo "<result>${v:-unknown}</result>"
```

A smart group on "agent state is not active" is the one worth alerting on.

## Step 6 - updating

**A new image** means a new machine: the disk is replaced, so containers, images
and volumes inside are lost. Treat it as a rebuild, announce it, and prefer Self
Service so the user picks the moment. Deploy the new package, then run the deploy
policy with `replace`.

**A new agent, same image** does not need a new machine. A small policy is
enough:

```bash
#!/bin/bash
# $4 = optional site token
set -uo pipefail
DIR="/Library/Application Support/PodmanMachine"
console_user=$(stat -f%Su /dev/console); console_uid=$(id -u "$console_user")
as_user() { launchctl asuser "$console_uid" sudo -u "$console_user" "$@"; }
PODMAN=/opt/podman/bin/podman

deb=$(ls "$DIR"/SentinelAgent*.deb 2>/dev/null | head -1)
[ -n "$deb" ] || { echo "ERROR: no agent package"; exit 1; }

as_user "$PODMAN" machine ssh podman-machine-default "cat > /tmp/s1.deb" < "$deb"
as_user "$PODMAN" machine ssh podman-machine-default \
    'sudo dpkg -i /tmp/s1.deb || sudo apt-get install -f -y; rm -f /tmp/s1.deb'
[ -n "${4:-}" ] && as_user "$PODMAN" machine ssh podman-machine-default \
    "sudo /opt/sentinelone/bin/sentinelctl management token set ${4}"
as_user "$PODMAN" machine ssh podman-machine-default 'sudo systemctl enable --now sentinelone'
as_user "$PODMAN" machine ssh podman-machine-default 'systemctl is-active sentinelone'
```

## Step 7 - removal

```bash
#!/bin/bash
console_user=$(stat -f%Su /dev/console); console_uid=$(id -u "$console_user")
as_user() { launchctl asuser "$console_uid" sudo -u "$console_user" "$@"; }
as_user /opt/podman/bin/podman machine stop podman-machine-default 2>/dev/null
as_user /opt/podman/bin/podman machine rm -f podman-machine-default 2>/dev/null
rm -rf "/Library/Application Support/PodmanMachine"
```

Removing the machine deletes its disk, and with it every container, image and
volume the user had.

## What to watch for

- **Disk space.** The machine's disk is sparse but grows to `--disk-size` (100 GB
  by default). A Mac with 30 GB free will fill up.
- **First boot pulls nothing**, but the image is decompressed and copied - budget
  a few minutes and a few GB of temporary space.
- **FileVault and login state.** No console user, no deployment. The script exits
  non-zero so Jamf retries.
- **Podman version drift.** The machine is created by the podman on the Mac. Keep
  the CLI version uniform across the fleet; podman's machine configuration format
  changes between major versions.
- **The agent in the VM is a second endpoint.** It reports as
  `<mac-hostname>-podman` and consumes a licence seat of its own. Whether it
  attributes container context to podman workloads is still open - see `TODO.md`.
