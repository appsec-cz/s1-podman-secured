# Troubleshooting

Every entry here is a failure that actually happened, with the symptom first -
because in each case the symptom pointed nowhere near the cause.

## `podman machine start` hangs forever, then the machine will not even stop

`podman machine stop` times out too, and the VM sits at 0% CPU. The serial log
(`$TMPDIR/podman/<machine>.log`) is empty.

The guest never got past GRUB. After the ext4 to btrfs conversion, the EFI stub
config still searched for the old filesystem UUID, GRUB could not find
`/boot/grub`, and it stopped at a rescue prompt waiting for a keypress - which
also explains why ACPI shutdown does nothing.

```bash
./tests/run.sh image      # checks exactly this, in seconds, without booting
```

The build gates on it now. If you hit it, the image was built before that gate
existed. Kill the VM through vfkit's API:

```bash
curl -s -X POST -H 'Content-Type: application/json' -d '{"state":"HardStop"}' \
  "$(podman machine inspect <machine> --format '{{.AppleHypervisor.Vfkit.Endpoint}}')/vm/state"
```

## Every `podman machine` command says `unknown machine state:`

Podman picks the port for vfkit's REST endpoint without checking whether it is
free. When it collides with another local service, every later command fails.

```bash
# find the port podman chose and who else has it
grep -o 'http://localhost:[0-9]*' ~/.config/containers/podman/machine/applehv/<machine>.json
lsof -nP -iTCP:<port>
# move it
sed -i '' 's/localhost:<port>/localhost:<free-port>/' \
  ~/.config/containers/podman/machine/applehv/<machine>.json
```

## `podman logs` returns nothing, and kind fails at "Preparing nodes"

kind reports:

```
could not find a log line that matches "Reached target .*Multi-User System.*"
```

The node container is fine - systemd inside it booted. The log is empty because
podman's default log driver is journald and the machine user could not read the
journal, so reading logs back returned silence.

```bash
podman machine ssh 'id -nG'     # must contain systemd-journal
podman machine ssh 'sudo usermod -aG systemd-journal core'   # then restart the machine
```

Images built after this fix add the group in `post-ignition-setup`.

## Published ports are unreachable from macOS

`podman run -p 8080:80` works inside the VM but `curl localhost:8080` on the Mac
gets nothing. `kubectl` cannot reach a kind cluster for the same reason.

Podman only asks gvproxy to forward a port when it recognises that it is running
inside a machine, and it decides that from `/etc/containers/podman-machine`.
Podman 6 mounts the host's `~/.config/containers` over `/etc/containers`, which
hides that marker.

```bash
podman machine ssh 'cat /etc/containers/podman-machine'          # should print something
podman machine ssh 'findmnt -no SOURCE,FSTYPE /etc/containers'   # virtiofs means it is shadowed
podman machine ssh 'curl -s http://192.168.127.1/services/forwarder/all'   # what gvproxy forwards
```

The Ignition provider skips that mount in current images. On an older machine,
`sudo umount /etc/containers` restores it until the next boot.

## `Error: no policy.json file found`

Nothing can be pulled. Same cause as above: `/etc/containers/policy.json` is
hidden by the host mount. `post-ignition-setup` now writes a fallback into the
user's own config directory; on an older machine:

```bash
podman machine ssh 'mkdir -p ~/.config/containers && \
  echo "{\"default\":[{\"type\":\"insecureAcceptAnything\"}]}" > ~/.config/containers/policy.json'
```

## The storage driver is overlay, not btrfs

```bash
podman machine ssh 'podman info --format "{{.Store.GraphDriverName}}"'
```

`storage.conf` was in `/etc/containers`, which the host mount hides. Current
images also write it to `/usr/share/containers/storage.conf`, which nothing
shadows. Note that a `containers.conf.d` drop-in under `/usr/share` is *not*
read - it has to be the file itself.

## Rootless commands fail with `RunRoot ... is not writable`

```
level=warning msg="RunRoot is pointing to a path (/run/containers/storage) which is not writable"
Error: configure storage: open /var/lib/containers/storage/storage.lock: permission denied
```

`storage.conf` pinned `runroot` and `graphroot` to the rootful paths. Podman 5.4
silently replaced them for rootless users; podman 5.8 honours them. Neither is
set any more - podman picks the right pair per mode. If you carry a local
`storage.conf`, remove those two keys.

## `prerequisites for driver not satisfied (wrong filesystem?)`

Anything using `--root` somewhere other than the btrfs root - `/tmp` is tmpfs -
fails when the driver is pinned. `storage.conf` uses
`driver_priority = ["btrfs", "overlay"]` so it falls back instead.

## x86_64 containers are slow, or Rosetta is not used

```bash
podman machine inspect --format '{{.Rosetta}}'
podman machine ssh 'ls /proc/sys/fs/binfmt_misc/ | grep -E "rosetta|qemu-x86_64"'
```

Two things go wrong here. Rosetta is decided when the machine is created, from
`[machine] rosetta = true` in the host's `containers.conf` - and podman
re-derives it on every start, so a value passed only at creation time is undone
by the next plain `podman machine start`. Put it in the real config file:

```bash
printf '\n[machine]\nrosetta = true\n' >> ~/.config/containers/containers.conf
# then recreate the machine
```

The second is ordering inside the VM: the activation unit must run *after*
`systemd-binfmt.service`, which flushes the binfmt table and re-registers only
its own rules. Registering before it looks successful in the journal and is gone
milliseconds later.

## A systemd unit is permanently failed

```bash
podman machine ssh 'systemctl list-units --state=failed'
```

`immutable-root-off.service` failing is the CoreOS-specific one - `chattr -i /`
on a Debian root that is still read-only at that point. Current images skip it.
Anything else is worth reading the journal for.

## The SentinelOne agent is installed but not running

Installing the package enables the unit without starting it, so an agent
installed into a running machine sits idle until the next reboot.

```bash
podman machine ssh 'sudo systemctl enable --now sentinelone'
podman machine ssh 'sudo /opt/sentinelone/bin/sentinelctl control status'
```

`deploy.sh` does this itself now, with or without a token.

## Podman Desktop shows a stale or unavailable machine

Podman Desktop caches the machine list and its connection. Replacing a machine
under a running Desktop leaves it pointing at a socket and ssh port that no
longer exist. Quit and reopen it.

The same applies to Kubernetes: a kind cluster lives *inside* the machine, so
replacing the machine deletes the cluster while the kubeconfig context stays
behind, pointing at a port nothing listens on.

## Collecting evidence

```bash
podman machine ssh 'sudo journalctl -b --no-pager | tail -200'
podman machine ssh 'systemctl list-units --state=failed'
podman machine ssh 'podman info'
cat "$TMPDIR/podman/<machine>.log"              # serial console
cat "$TMPDIR/podman/gvproxy.log"                # network and port forwarding
podman machine ssh 'curl -s http://192.168.127.1/services/forwarder/all'
```

For anything reproducible, the test suite localises it faster than reading logs:
`./tests/run.sh integration` names the property that broke.
