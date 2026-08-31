# Using the machine

Once deployed, this is an ordinary podman machine. What follows is the part that
is specific to this image, with examples.

## Deploying one

```bash
cd ~/podman-deploy          # holds podman-debian.raw.zst and SentinelAgent*.deb
./deploy.sh                 # image and agent are auto-detected
./deploy.sh --token eyJ...  # and register the agent
./deploy.sh --cpus 8 --memory 8192 --disk-size 200
./deploy.sh --image /path/to/podman-debian.raw.zst
```

The machine is always called `podman-machine-default`, so Podman Desktop and a
bare `podman` command find it without configuration. Deploying again over an
existing machine asks first, and deletes it - **everything inside is lost**,
including images, volumes and any kind cluster.

## Everyday use

```bash
podman run --rm alpine echo hello
podman run -d --name web -p 8080:80 nginx:alpine
curl localhost:8080                       # published ports reach macOS
podman logs web
podman exec -it web sh
podman ps -a
```

Short names work (`alpine`, not `docker.io/library/alpine`), `--init` works, and
`podman build` is available.

### x86_64 images on Apple Silicon

```bash
podman run --rm --arch amd64 alpine uname -m     # x86_64
```

Rosetta does the translation - a container that would crawl under emulation runs
at close to native speed. Check which path is active:

```bash
podman machine ssh 'ls /proc/sys/fs/binfmt_misc/ | grep -E "rosetta|qemu-x86_64"'
```

`rosetta` means Apple's translator; `qemu-x86_64` means emulation, which is the
fallback when Rosetta is unavailable.

### Volumes and the host filesystem

`/Users`, `/private` and `/var/folders` are shared into the VM, so paths under
your home directory mount straight through:

```bash
podman run --rm -v "$PWD:/src:z" -w /src alpine ls
```

Paths outside those three are not visible to the VM.

### Compose

```bash
podman compose up -d          # podman's own compose front end
docker-compose up -d          # inside the machine, talks to the same engine
```

### Kubernetes YAML

```bash
podman kube play app.yaml
podman kube down app.yaml
```

### A real cluster with kind

```bash
export KIND_EXPERIMENTAL_PROVIDER=podman
kind create cluster --name dev
kubectl get nodes
```

kind depends on two things this image gets right and that broke before: `podman
logs` must return output (kind waits for the node to log that systemd reached
multi-user), and the API server's published port must reach macOS. If
`kind create` hangs on "Preparing nodes", see
[troubleshooting.md](troubleshooting.md).

## Docker compatibility

Inside the machine, `docker` is podman and `/var/run/docker.sock` is podman's
API socket, which answers as `Podman Engine` at Docker API 1.41.

On the Mac, a Docker API client needs one of:

```bash
# either point it at the machine explicitly
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"

# or wire up the standard socket once, so clients that hardcode it work
sudo podman-mac-helper install
podman machine stop && podman machine start
```

The helper is what makes testcontainers, IDE integrations and anything else that
opens `/var/run/docker.sock` work without configuration.

## Storage

The machine stores images as btrfs subvolumes:

```bash
podman machine ssh 'sudo btrfs subvolume list / | head'
podman machine ssh 'df -h /'
podman system df
```

Rootless containers live in `~/.local/share/containers/storage` inside the VM,
rootful ones in `/var/lib/containers/storage`. Both use btrfs.

## The SentinelOne agent

```bash
podman machine ssh 'systemctl is-active sentinelone'
podman machine ssh 'sudo /opt/sentinelone/bin/sentinelctl control status'
podman machine ssh 'sudo /opt/sentinelone/bin/sentinelctl management status'
```

Registering after the fact:

```bash
podman machine ssh 'sudo /opt/sentinelone/bin/sentinelctl management token set <TOKEN>'
podman machine ssh 'sudo systemctl restart sentinelone'
```

The VM reports itself as `<your-mac-hostname>-podman`, which is how to find it in
the console.

## Machine lifecycle

```bash
podman machine list
podman machine stop
podman machine start
podman machine ssh
podman machine inspect --format '{{.Rosetta}} {{.Resources.CPUs}} {{.Resources.Memory}}'
```

CPUs, memory and disk are fixed when the machine is created. Changing them means
deploying again, which destroys the current machine's contents - unless you ask
for them to be carried across.

## Keeping your data across a new image

`podman machine rm` takes the disk with it, so a plain redeploy costs every
image, volume and container in the machine. `--preserve` exports them first and
puts them back afterwards:

```bash
./deploy.sh --preserve --token <site-token>
```

The two halves also stand on their own, which is useful before doing anything
drastic by hand:

```bash
./deploy.sh --backup-only            # prints the directory it wrote
./deploy.sh --restore <directory>
```

Backups live in `~/.local/share/containers/podman/machine/backups/`. A restore
that verifies deletes the backup it came from, because at that point the data
exists twice and the copy in the machine is the one being used. Pass
`--keep-backup` to hold on to it anyway.

What travels:

- **Images** through `podman save`, all of them that carry a name.
- **Volumes** through `podman volume export`, recreated first with the driver,
  labels and options they had.
- **Pods, whole**, through `podman kube generate --podman-only`. A container that
  belongs to a pod cannot be generated on its own - podman refuses with "use
  generate on the pod itself" - so anything composed is taken as a pod, and only
  containers outside any pod are taken individually. One file each, because
  generating several together would put unrelated containers in a pod and hand
  them a network namespace they never shared.
- **Running state**, per container - what was running is started again, what was
  stopped stays stopped, including a pod with only some of its containers up.

What does not:

- **kind nodes.** A node is a running kubelet with etcd behind it, and replaying
  its definition does not give back a working cluster. They are listed and
  skipped; rebuild those clusters with kind.
- **Anything `podman kube generate` cannot express.** Such containers are named
  in the output; `containers.json` and `pods.json` in the backup hold the full
  state of everything carried, including whatever could not be expressed, to
  rebuild by hand.
- **Standalone-ness.** Podman always generates a pod, so a restored container
  comes back inside a pod of its own and `podman ps -a` gains an infra container
  next to it. `--no-pod-prefix` keeps the container under its original name, and
  ports, mounts and restart policy all behave as before, but the shape is a pod
  rather than a lone container.
- **The SentinelOne agent's identity.** Anti-tamper protects
  `/opt/sentinelone/configuration`, and a copied UUID registers as a cloned
  agent. The new machine registers itself with `--token`, so the console ends up
  with two endpoints of the same name - the summary prints the site key of the
  old one to decommission.

The store is exported straight onto the Mac: `$HOME` is under `/Users`, which the
machine mounts at the same path, so gigabytes never travel through the ssh
connection. Expect to need about as much free space as the store occupies.

## Running a playbook on a new machine

`podman machine init --playbook` is supported: podman writes the file to
`/home/core/playbook.yaml` inside the guest and a `playbook.service` runs it once
the machine reports ready.

```bash
podman machine init --playbook ./setup.yaml --image podman-debian.raw.zst
```

The image carries `ansible-core`, so this works with no route to a Debian mirror.
It is `ansible-core` rather than the full `ansible`: `ansible-playbook` is all the
unit runs, and the difference is 37 packages instead of several hundred. Anything
your playbook needs beyond the bundled collections has to be installed by the
playbook itself.

One adjustment happens on the way in. Podman writes that unit for Fedora CoreOS
and gates it on `ConditionFirstBoot=yes`, which is never true here - this image
ships `/etc/machine-id` empty and systemd still does not call the result a first
boot, which is why `sshd-keygen` is not trusted with host keys either. Left alone
the playbook would be skipped on every boot without a word, so the Ignition
provider swaps that condition for a marker at `/var/lib/podman-machine-playbook-done`
and has the unit create it. The "only once" promise is kept; delete the marker to
run the playbook again.

## What is deliberately absent

- **No Docker Engine.** `docker` is podman. Adding dockerd was tried and removed:
  it conflicts with `podman-docker`, and the Ignition config points `docker` at
  podman anyway.
- **No swap, no auto-update.** Rebuild the image instead.
- **No USB passthrough.** The Apple hypervisor does not support it.
