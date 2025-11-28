# TODO - Future Improvements

Based on comprehensive audit of Podman Desktop and Podman machine source code.

## Current Status

Implementation is **production-ready** with all critical features correctly implemented:
- vsock port 1024 (Ignition config delivery) - correct
- vsock port 1025 (Ready signal) - correct
- Ignition provider handles all v3.x fields
- Boot sequence: Ignition -> Network -> SSH -> Ready
- Rosetta x86_64 binary translation
- Registry configuration for Podman Desktop

## Priority 1: Short-term Improvements

### 1.1 Fallback podman.socket Enablement
**File**: `resources/scripts/post-ignition-setup.sh`

Add fallback enablement of `podman.socket` if not already enabled by Ignition.
Podman Desktop sends this in config, but having a fallback improves reliability.

```bash
# Enable podman.socket if not already enabled
if ! systemctl is-enabled podman.socket &>/dev/null; then
    systemctl enable --now podman.socket
fi
```

### 1.2 SSL Certificate Handling
**Impact**: Enterprise users with private registries

Copy host SSL certificates to VM for private registry access:
- Source: Host's certificate store via virtiofs
- Destination: `/etc/containers/certs.d/`

### 1.3 Diagnostic Logging Improvements
**File**: `resources/scripts/podman-machine-ready.sh`

Add more detailed logging during boot:
- Log systemd service states
- Log network interface status
- Log vsock connection attempts

## Priority 2: Medium-term Enhancements

### 2.1 Health Check Endpoint
Add vsock endpoint for remote health checks:
- Report systemd service status
- Report container runtime status
- Help debugging stuck machines

### 2.2 Timezone Support
Support `--timezone` parameter from `podman machine init`:
- Parse timezone from Ignition config
- Set `/etc/localtime` symlink appropriately

### 2.3 Volume Mount Validation (Build-time)
Warn about forbidden mount paths during build:
- `/bin`, `/boot`, `/dev`, `/etc`, `/home`
- `/proc`, `/root`, `/run`, `/sbin`
- `/sys`, `/tmp`, `/usr`, `/var`

## Priority 3: Long-term Features

### 3.1 Ansible Playbook Support
Support `--playbook` parameter for custom configurations:
- Install Ansible in base image
- Execute playbook after Ignition completes
- Useful for enterprise customization

### 3.2 gvforwarder Installation
Monitor for networking issues; add if needed:
- Package: `gvisor-tap-vsock-gvforwarder`
- Currently works without it on newer vfkit

### 3.3 Machine Inspection Endpoint
Add endpoint for `podman machine inspect` compatibility:
- Report machine configuration
- Report resource usage
- Report installed packages

## Not Planned

### USB Passthrough
- Only available with QEMU provider
- AppleHV doesn't support USB passthrough
- Document limitation in README

### Zincati Auto-updates
- Fedora CoreOS feature
- Not applicable to Debian base
- Manual updates via rebuild preferred

## Completed Features

- [x] vsock port 1024 - Ignition config fetch
- [x] vsock port 1025 - Ready signal
- [x] User creation with SSH keys
- [x] File/directory/symlink creation
- [x] Systemd unit management
- [x] Rosetta x86_64 activation
- [x] Registry configuration symlinks
- [x] Enhanced hostname for SentinelOne
- [x] SentinelOne agent integration
- [x] subuid/subgid from Ignition (not overwritten)
- [x] Docker socket symlink
- [x] Podman Desktop compatibility

## References

- [Podman Machine Documentation](https://docs.podman.io/en/latest/markdown/podman-machine.1.html)
- [Ignition Specification v3.5](https://coreos.github.io/ignition/configuration-v3_5/)
- [vfkit Documentation](https://github.com/crc-org/vfkit)
- [Podman AppleHV Issues](https://github.com/containers/podman/issues?q=applehv)
