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

## `podman machine start` fails with `ssh: handshake failed: EOF`

The VM boots - the serial console shows a Debian login prompt - but ssh never
answers, so podman gives up after about twenty seconds and kills gvproxy. Trying
again usually works; when it does not, leftover processes from a previous stop
are in the way:

```bash
pkill -f 'vfkit.*podman-machine-default'
pkill -f gvproxy
podman machine start podman-machine-default
```

Seen repeatedly on this host, always after a stop, and always cured by clearing
those processes and retrying. The machine test layer retries once for the same
reason and reports when it had to.

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

The node container is fine - systemd inside it booted and reached multi-user in
well under a second. kind waits for that line by streaming `podman logs --follow`
from macOS, and that stream came back empty: podman's default log driver is
journald, and the podman API service in the guest could not read the journal.

Note that a guest shell can read it perfectly well at the same time, because a
fresh login picks up the current groups. Only the long-lived API service is
affected, so `podman machine ssh 'podman logs ...'` is not a useful check here -
read the logs the way kind does instead:

```bash
podman logs --follow <container>              # from macOS: must not be silent
podman machine ssh 'id -nG'                   # contains systemd-journal
podman machine ssh 'grep Groups /proc/$(systemctl --user show -p MainPID --value podman.service)/status'
```

Group 999 is `systemd-journal`; the service having only 1000 is the fault. Do not
reach for `pgrep -f "podman system service"` here - `-f` matches full command
lines, so it finds the shell running your own check, reports the groups of a
fresh login, and tells you everything is fine.

If the last two disagree, this is the first-boot race: `post-ignition-setup` adds
`core` to `systemd-journal`, but logind had already started `user@501.service` for
the lingering user, and a process keeps the supplementary groups it started with -
so the rootless podman service inside that manager runs without journal access for
the rest of the boot. **Restarting the machine fixes it**, which is why the symptom
only ever appeared right after `deploy.sh`.

Images built after this fix order `post-ignition-setup` before
`systemd-user-sessions.service` and restart the user manager if it started anyway.

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
