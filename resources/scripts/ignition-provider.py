#!/usr/bin/env python3
"""
Ignition Provider for Podman Machine on Debian

This service fetches Ignition configuration from the host via vsock
and applies the configuration (users, SSH keys, files, systemd units).

Compatible with Podman Desktop AppleHV provider which sends Ignition
config over vsock port 1024.
"""

import json
import os
import re
import sys
import socket
import subprocess
import logging
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Any, Optional
import base64

# Configure logging
# The log file is best effort: the provider runs as root at boot, where it always
# works, but the module is also imported by the unit tests off the VM. A missing
# or read-only /var/log must not stop the provider from running.
_log_handlers = [logging.StreamHandler(sys.stdout)]
try:
    _log_handlers.append(logging.FileHandler('/var/log/ignition-provider.log'))
except OSError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=_log_handlers
)
logger = logging.getLogger('ignition-provider')

# Vsock constants
VMADDR_CID_HOST = 2  # Host CID in vsock
IGNITION_VSOCK_PORT = 1024  # Port where vfkit serves Ignition config


# Units from the Ignition config that must NOT be applied.
#
# Podman 6 ships etc-containers.mount, which bind mounts the host's
# ~/.config/containers over /etc/containers inside the VM. That hides every file
# the image puts there, and the guest runs podman 5.4.2 (Debian trixie), which
# still reads them from /etc/containers:
#   - podman-machine  -> without this marker podman does not recognise it runs in
#     a machine, so it never asks gvproxy to forward published container ports and
#     nothing published in the VM is reachable from the host (this breaks kind)
#   - storage.conf, containers.conf -> storage driver and runtime settings ignored
#   - policy.json     -> no image can be pulled at all
# The host's registry configuration still reaches the VM: setup_registries_symlink()
# links /etc/containers/registries.conf.d/999-podman-desktop.conf to the host file
# over the /Users virtiofs mount. Credentials in the host's auth.json are not shared
# into the VM; the remote client sends them with the request instead.
# immutable-root-{on,off} exist for Fedora CoreOS, whose root filesystem is
# chattr +i. Debian's is not, so 'chattr -i /' only fails - it runs at
# local-fs-pre.target while the root is still read only - and leaves a permanently
# failed unit behind, which hides real failures in 'systemctl --failed'.
SKIPPED_UNITS = {
    'etc-containers.mount': 'would hide /etc/containers provided by the image',
    'immutable-root-off.service': 'Debian root is not immutable; chattr -i / always fails',
    'immutable-root-on.service': 'Debian root is not immutable; nothing to set back',
}


# Directories a virtiofs share must never be mounted over. etc-containers.mount
# above is one instance of this: a share landing on a system directory hides
# everything the image put there, and the damage shows up later as something
# unrelated - no image can be pulled, no published port is forwarded, the storage
# driver is suddenly overlay.
#
# Matched exactly, never as a prefix. Podman's own default shares include
# /var/folders, so rejecting everything under /var would reject a stock machine;
# it is mounting *over* /var that destroys it.
FORBIDDEN_MOUNT_TARGETS = {
    '/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/proc',
    '/root', '/run', '/sbin', '/sys', '/tmp', '/usr', '/var',
}


# Marker that keeps "podman machine init --playbook" a first boot affair once its
# own first boot condition has been taken away.
PLAYBOOK_DONE_MARKER = '/var/lib/podman-machine-playbook-done'


def adapt_playbook_unit(contents: Optional[str]) -> Optional[str]:
    """
    Make podman's playbook.service capable of running in this image.

    podman writes it for Fedora CoreOS and gates it on ConditionFirstBoot=yes.
    That condition is never true here: the build ships /etc/machine-id empty, and
    systemd still does not call the result a first boot - on this machine's very
    first boot systemd-firstboot, first-boot-complete.target and sshd-keygen were
    all skipped for exactly that reason, which is also why host keys are not left
    to sshd-keygen. Applied unchanged, the playbook would be skipped on every boot
    for ever, and say nothing while doing it.

    A marker file replaces it, which keeps the "only once" promise without
    depending on systemd's idea of a first boot. After=ready.service is left
    alone: podman puts that unit in the same config, and it is real here.
    """
    if not contents:
        return contents

    out = []
    replaced = False
    for line in contents.splitlines():
        if line.strip().lower().startswith('conditionfirstboot='):
            out.append('ConditionPathExists=!' + PLAYBOOK_DONE_MARKER)
            replaced = True
            continue
        out.append(line)
        # '+' runs this one as root: the unit itself runs as the machine user,
        # who cannot write to /var/lib.
        if line.strip().lower().startswith('execstart='):
            out.append('ExecStartPost=+/bin/touch ' + PLAYBOOK_DONE_MARKER)

    if not replaced:
        # Nothing gated it, so nothing would stop it running on every boot.
        out.append('ConditionPathExists=!' + PLAYBOOK_DONE_MARKER)

    return '\n'.join(out) + ('\n' if contents.endswith('\n') else '')


def mount_unit_target(contents: Optional[str]) -> Optional[str]:
    """
    The Where= of a .mount unit, normalised for comparison.

    Systemd takes the last assignment when a key repeats, so this does too.
    """
    if not contents:
        return None

    target = None
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        key, sep, value = line.partition('=')
        if sep and key.strip().lower() == 'where':
            target = value.strip()

    if not target:
        return None

    # /usr/, //usr and /usr/. all name the same directory as /usr. Collapse the
    # leading slashes first: POSIX leaves a leading '//' implementation defined
    # and os.path.normpath preserves exactly two, so '//usr' would otherwise walk
    # straight past the check below.
    target = re.sub(r'^/+', '/', target)
    normalised = os.path.normpath(target)
    return normalised if normalised == '/' else normalised.rstrip('/')


def _recv_exactly(sock, n: int) -> bytes:
    """Read exactly n bytes; a peer that closes early is an error, not a hang."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(4096, n - len(data)))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(data)} of {n} bytes")
        data += chunk
    return data


def _recv_line(sock) -> bytes:
    line = b""
    while not line.endswith(b"\r\n"):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("connection closed inside a chunked body")
        line += byte
    return line


def read_chunked_body(sock) -> bytes:
    """
    Read an HTTP/1.1 chunked body.

    recv() returns b"" once the peer has closed, immediately and for ever, so
    the socket timeout never fires. The loop this replaces appended that to the
    chunk and asked again, and a host that went away mid-chunk held the boot
    for good. recv(2) for the CRLFs could also come back short and leave the
    next size line misaligned.
    """
    body = b""
    while True:
        # Chunk extensions (";name=value") are allowed after the size.
        size_field = _recv_line(sock).split(b";", 1)[0].strip()
        chunk_size = int(size_field, 16)
        if chunk_size == 0:
            # Trailer headers, if any, up to the empty line that ends the body.
            while _recv_line(sock) != b"\r\n":
                pass
            return body
        body += _recv_exactly(sock, chunk_size)
        if _recv_exactly(sock, 2) != b"\r\n":
            raise ValueError("chunk not followed by CRLF")


class IgnitionProvider:
    """Fetches and applies Ignition configuration from vsock."""

    def __init__(self):
        self.config: Optional[Dict[str, Any]] = None

    def fetch_config_from_vsock(self) -> Optional[Dict[str, Any]]:
        """
        Fetch Ignition config from host via vsock HTTP GET.

        Returns:
            Parsed JSON config or None if unavailable
        """
        try:
            logger.info(f"Connecting to vsock CID {VMADDR_CID_HOST}, port {IGNITION_VSOCK_PORT}")

            # Create vsock socket
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            # Use longer timeout - original Ignition has no timeout
            # But we set 30s as safety measure to avoid hanging forever
            sock.settimeout(30)

            # Connect to host
            sock.connect((VMADDR_CID_HOST, IGNITION_VSOCK_PORT))
            logger.info("Connected to vsock")

            # Send HTTP GET request
            # Match the format used by CoreOS Ignition applehv provider:
            # - Path: / (root, not /config)
            # - Accept: application/json header
            # - HTTP/1.1 (not 1.0)
            http_request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: ignition\r\n"
                b"Accept: application/json\r\n"
                b"\r\n"
            )
            sock.sendall(http_request)
            logger.info("Sent HTTP GET request (format: GET / HTTP/1.1, Accept: application/json)")

            # Receive response
            # First, read headers to get Content-Length
            response = b""
            headers_complete = False
            headers_bytes = b""

            logger.info("Reading HTTP headers...")
            while not headers_complete:
                chunk = sock.recv(1)  # Read byte by byte to find headers end
                if not chunk:
                    raise ConnectionError("Connection closed before headers complete")
                response += chunk
                if response.endswith(b"\r\n\r\n"):
                    headers_complete = True
                    headers_bytes = response[:-4]  # Remove trailing \r\n\r\n
                    logger.info(f"Headers complete ({len(headers_bytes)} bytes)")
                    break

            # Parse headers to find Content-Length and Transfer-Encoding
            headers_text = headers_bytes.decode('utf-8', errors='ignore')
            logger.info(f"Response headers:\n{headers_text}")

            content_length = None
            transfer_encoding = None
            for line in headers_text.split('\r\n'):
                lower_line = line.lower()
                if lower_line.startswith('content-length:'):
                    content_length = int(line.split(':', 1)[1].strip())
                    logger.info(f"Content-Length: {content_length}")
                elif lower_line.startswith('transfer-encoding:'):
                    transfer_encoding = line.split(':', 1)[1].strip().lower()
                    logger.info(f"Transfer-Encoding: {transfer_encoding}")

            # Read body based on Content-Length or chunked encoding
            if content_length is not None:
                bytes_to_read = content_length
                body_bytes = b""

                logger.info(f"Reading {content_length} bytes of body...")
                while len(body_bytes) < bytes_to_read:
                    chunk_size = min(4096, bytes_to_read - len(body_bytes))
                    chunk = sock.recv(chunk_size)
                    if not chunk:
                        logger.warning(f"Connection closed after {len(body_bytes)}/{bytes_to_read} bytes")
                        break
                    body_bytes += chunk

                logger.info(f"Received body: {len(body_bytes)} bytes")
            elif transfer_encoding == 'chunked':
                # Read chunked transfer encoding
                logger.info("Reading chunked body...")
                body_bytes = read_chunked_body(sock)

                logger.info(f"Received chunked body: {len(body_bytes)} bytes")
            else:
                # No Content-Length, try to read available data with short timeout
                # vfkit may keep connection open, so we use a short read timeout
                logger.warning("No Content-Length header, reading with short timeout")
                sock.settimeout(2)  # 2 second timeout for reading body
                body_bytes = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        body_bytes += chunk
                        logger.info(f"Read chunk: {len(chunk)} bytes, total: {len(body_bytes)}")
                except socket.timeout:
                    logger.info(f"Read timeout (expected), body size: {len(body_bytes)} bytes")

                if not body_bytes:
                    logger.error("No body data received!")
                else:
                    logger.info(f"Received body: {len(body_bytes)} bytes")

            sock.close()

            # Parse JSON
            try:
                config = json.loads(body_bytes.decode('utf-8'))
                logger.info(f"Parsed Ignition config version {config.get('ignition', {}).get('version', 'unknown')}")

                # Save config to disk for debugging
                with open('/run/ignition-config.json', 'w') as f:
                    json.dump(config, f, indent=2)

                return config

            except ValueError as e:
                logger.error(f"Failed to parse JSON: {e}")
                logger.error(f"Body preview: {body_bytes[:500]}")
                return None
            except Exception as e:
                logger.error(f"Failed to parse response: {e}")
                return None

        except socket.timeout:
            logger.warning("Timeout connecting to vsock - Ignition config not available")
            return None
        except OSError as e:
            logger.warning(f"Failed to connect to vsock: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching config: {e}", exc_info=True)
            return None

    def create_user(self, user_config: Dict[str, Any]) -> None:
        """
        Create a user from Ignition config.

        Args:
            user_config: User configuration dict
        """
        username = user_config.get('name')
        if not username:
            logger.warning("User config missing 'name' field")
            return

        # Check shouldExist field (Ignition 3.2.0+)
        should_exist = user_config.get('shouldExist', True)
        if not should_exist:
            # Delete user if shouldExist is false
            try:
                pwd.getpwnam(username)
                logger.info(f"Deleting user '{username}' (shouldExist=false)")
                subprocess.run(['userdel', '-r', username], check=True, capture_output=True)
                logger.info(f"Deleted user '{username}'")
            except KeyError:
                logger.info(f"User '{username}' doesn't exist, nothing to delete")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to delete user '{username}': {e.stderr.decode()}")
            return

        # Check if user already exists
        try:
            pwd.getpwnam(username)
            logger.info(f"User '{username}' already exists")
        except KeyError:
            # User doesn't exist, create it
            logger.info(f"Creating user '{username}'")

            cmd = ['useradd', '-m', '-s', '/bin/bash']

            # Add UID if specified
            uid = user_config.get('uid')
            if uid is not None:
                cmd.extend(['-u', str(uid)])

            # Add primary group if specified
            primary_group = user_config.get('primaryGroup')
            if primary_group:
                cmd.extend(['-g', primary_group])

            # Add username
            cmd.append(username)

            try:
                subprocess.run(cmd, check=True, capture_output=True)
                logger.info(f"Created user '{username}'")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create user '{username}': {e.stderr.decode()}")
                return

        # Add user to groups
        groups = user_config.get('groups', [])
        if groups:
            # Add special handling for 'sudo' -> 'sudo' group
            processed_groups = []
            for group in groups:
                if group == 'wheel':
                    # On Debian, use 'sudo' instead of 'wheel'
                    processed_groups.append('sudo')
                else:
                    processed_groups.append(group)

            if processed_groups:
                try:
                    subprocess.run(
                        ['usermod', '-a', '-G', ','.join(processed_groups), username],
                        check=True,
                        capture_output=True
                    )
                    logger.info(f"Added user '{username}' to groups: {', '.join(processed_groups)}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to add user to groups: {e.stderr.decode()}")

        # Set password hash if specified
        password_hash = user_config.get('passwordHash')
        if password_hash:
            try:
                subprocess.run(
                    ['usermod', '-p', password_hash, username],
                    check=True,
                    capture_output=True
                )
                logger.info(f"Set password hash for user '{username}'")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to set password hash: {e.stderr.decode()}")

        # Set up SSH keys
        ssh_keys = user_config.get('sshAuthorizedKeys', [])
        if ssh_keys:
            self.install_ssh_keys(username, ssh_keys)

    def install_ssh_keys(self, username: str, ssh_keys: List[str]) -> None:
        """
        Install SSH authorized keys for a user.

        Args:
            username: Username
            ssh_keys: List of SSH public keys
        """
        try:
            user_info = pwd.getpwnam(username)
            home_dir = Path(user_info.pw_dir)
            ssh_dir = home_dir / '.ssh'
            authorized_keys_dir = ssh_dir / 'authorized_keys.d'
            ignition_keys_file = authorized_keys_dir / 'ignition'

            # Create .ssh directory
            ssh_dir.mkdir(mode=0o700, exist_ok=True)
            ssh_dir.chmod(0o700)

            # Create authorized_keys.d directory
            authorized_keys_dir.mkdir(mode=0o700, exist_ok=True)
            authorized_keys_dir.chmod(0o700)

            # Write keys to ignition file
            with open(ignition_keys_file, 'w') as f:
                for key in ssh_keys:
                    f.write(f"{key}\n")

            ignition_keys_file.chmod(0o600)

            # Set ownership
            os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
            os.chown(authorized_keys_dir, user_info.pw_uid, user_info.pw_gid)
            os.chown(ignition_keys_file, user_info.pw_uid, user_info.pw_gid)

            logger.info(f"Installed {len(ssh_keys)} SSH key(s) for user '{username}'")

            # Also ensure SSH is configured to read from authorized_keys.d
            self.configure_ssh_authorized_keys_command(username)

        except Exception as e:
            logger.error(f"Failed to install SSH keys for '{username}': {e}", exc_info=True)

    def configure_ssh_authorized_keys_command(self, username: str) -> None:
        """
        Configure SSH to read keys from authorized_keys.d directory.

        Args:
            username: Username
        """
        try:
            user_info = pwd.getpwnam(username)
            home_dir = Path(user_info.pw_dir)
            ssh_dir = home_dir / '.ssh'
            authorized_keys_file = ssh_dir / 'authorized_keys'
            authorized_keys_dir = ssh_dir / 'authorized_keys.d'

            # Merge all keys from authorized_keys.d into authorized_keys
            if authorized_keys_dir.exists():
                all_keys = []

                # Read existing authorized_keys
                if authorized_keys_file.exists():
                    with open(authorized_keys_file, 'r') as f:
                        all_keys.extend([line.strip() for line in f if line.strip()])

                # Read keys from authorized_keys.d/*
                for key_file in authorized_keys_dir.glob('*'):
                    if key_file.is_file():
                        with open(key_file, 'r') as f:
                            all_keys.extend([line.strip() for line in f if line.strip()])

                # Write merged keys
                if all_keys:
                    # Remove duplicates while preserving order
                    seen = set()
                    unique_keys = []
                    for key in all_keys:
                        if key not in seen:
                            seen.add(key)
                            unique_keys.append(key)

                    with open(authorized_keys_file, 'w') as f:
                        for key in unique_keys:
                            f.write(f"{key}\n")

                    authorized_keys_file.chmod(0o600)
                    os.chown(authorized_keys_file, user_info.pw_uid, user_info.pw_gid)

                    logger.info(f"Merged {len(unique_keys)} SSH key(s) into authorized_keys for '{username}'")

        except Exception as e:
            logger.error(f"Failed to configure authorized_keys for '{username}': {e}", exc_info=True)

    def create_file(self, file_config: Dict[str, Any]) -> None:
        """
        Create a file from Ignition config.

        Args:
            file_config: File configuration dict
        """
        path = file_config.get('path')
        if not path:
            logger.warning("File config missing 'path' field")
            return

        logger.info(f"Creating file '{path}'")

        # Get file contents
        contents = file_config.get('contents', {})
        source = contents.get('source', '')

        # Decode content
        file_content = ''
        if source.startswith('data:'):
            # Data URI format
            try:
                # Parse data URI: data:[<mediatype>][;base64],<data>
                parts = source.split(',', 1)
                if len(parts) == 2:
                    encoding_info = parts[0]
                    data = parts[1]

                    if 'base64' in encoding_info:
                        file_content = base64.b64decode(data).decode('utf-8')
                    else:
                        # URL-decode plain data (e.g., %20 -> space)
                        import urllib.parse
                        file_content = urllib.parse.unquote(data)
            except Exception as e:
                logger.error(f"Failed to decode file content: {e}")
                return

        # Create parent directories
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        try:
            with open(file_path, 'w') as f:
                f.write(file_content)

            # Set mode
            mode = file_config.get('mode')
            if mode is not None:
                file_path.chmod(mode)

            # Set ownership
            user = file_config.get('user', {})
            group = file_config.get('group', {})

            uid = -1
            gid = -1

            if user:
                username = user.get('name')
                if username:
                    try:
                        uid = pwd.getpwnam(username).pw_uid
                    except KeyError:
                        logger.warning(f"User '{username}' not found for file '{path}'")

            if group:
                groupname = group.get('name')
                if groupname:
                    try:
                        gid = grp.getgrnam(groupname).gr_gid
                    except KeyError:
                        logger.warning(f"Group '{groupname}' not found for file '{path}'")

            if uid != -1 or gid != -1:
                os.chown(file_path, uid, gid)

            logger.info(f"Created file '{path}'")

        except Exception as e:
            logger.error(f"Failed to create file '{path}': {e}", exc_info=True)

    def create_directory(self, dir_config: Dict[str, Any]) -> None:
        """
        Create a directory from Ignition config.

        Args:
            dir_config: Directory configuration dict
        """
        path = dir_config.get('path')
        if not path:
            logger.warning("Directory config missing 'path' field")
            return

        logger.info(f"Creating directory '{path}'")

        try:
            dir_path = Path(path)

            # Create directory with parents
            mode = dir_config.get('mode', 0o755)
            dir_path.mkdir(parents=True, exist_ok=True, mode=mode)

            # Set ownership
            user = dir_config.get('user', {})
            group = dir_config.get('group', {})

            uid = -1
            gid = -1

            if user:
                username = user.get('name')
                if username:
                    try:
                        uid = pwd.getpwnam(username).pw_uid
                    except KeyError:
                        logger.warning(f"User '{username}' not found for directory '{path}'")

            if group:
                groupname = group.get('name')
                if groupname:
                    try:
                        gid = grp.getgrnam(groupname).gr_gid
                    except KeyError:
                        logger.warning(f"Group '{groupname}' not found for directory '{path}'")

            if uid != -1 or gid != -1:
                os.chown(dir_path, uid, gid)

            # Set mode explicitly (mkdir mode might be affected by umask)
            if mode is not None:
                dir_path.chmod(mode)

            logger.info(f"Created directory '{path}'")

        except Exception as e:
            logger.error(f"Failed to create directory '{path}': {e}", exc_info=True)

    def create_link(self, link_config: Dict[str, Any]) -> None:
        """
        Create a symbolic link from Ignition config.

        Args:
            link_config: Link configuration dict
        """
        path = link_config.get('path')
        target = link_config.get('target')

        if not path or not target:
            logger.warning("Link config missing 'path' or 'target' field")
            return

        logger.info(f"Creating symlink '{path}' -> '{target}'")

        try:
            link_path = Path(path)
            overwrite = link_config.get('overwrite', False)

            # Create parent directories
            link_path.parent.mkdir(parents=True, exist_ok=True)

            # exists() follows a symlink, so a dangling one reads as absent:
            # it was neither replaced nor skipped, and symlink_to() then failed
            # on it. lexists() asks about the link itself.
            present = os.path.lexists(link_path)

            # Remove existing link/file if overwrite is true
            if overwrite and present:
                if link_path.is_symlink() or link_path.is_file():
                    link_path.unlink()
                elif link_path.is_dir():
                    import shutil
                    shutil.rmtree(link_path)
                present = False

            # Create symlink
            if not present:
                link_path.symlink_to(target)

                # Set ownership (note: symlinks don't have permissions)
                user = link_config.get('user', {})
                group = link_config.get('group', {})

                uid = -1
                gid = -1

                if user:
                    username = user.get('name')
                    if username:
                        try:
                            uid = pwd.getpwnam(username).pw_uid
                        except KeyError:
                            logger.warning(f"User '{username}' not found for link '{path}'")

                if group:
                    groupname = group.get('name')
                    if groupname:
                        try:
                            gid = grp.getgrnam(groupname).gr_gid
                        except KeyError:
                            logger.warning(f"Group '{groupname}' not found for link '{path}'")

                if uid != -1 or gid != -1:
                    os.lchown(link_path, uid, gid)

                logger.info(f"Created symlink '{path}' -> '{target}'")
            else:
                logger.info(f"Symlink '{path}' already exists")

        except Exception as e:
            logger.error(f"Failed to create symlink '{path}': {e}", exc_info=True)

    def enable_systemd_unit(self, unit_config: Dict[str, Any]) -> None:
        """
        Enable/start a systemd unit from Ignition config.

        Args:
            unit_config: Systemd unit configuration dict
        """
        name = unit_config.get('name')
        if not name:
            logger.warning("Systemd unit config missing 'name' field")
            return

        if name in SKIPPED_UNITS:
            logger.info(f"Skipping systemd unit '{name}': {SKIPPED_UNITS[name]}")
            return

        enabled = unit_config.get('enabled', False)
        contents = unit_config.get('contents')
        dropins = unit_config.get('dropins', [])

        if name == 'playbook.service':
            contents = adapt_playbook_unit(contents)
            logger.info(
                "Adapted playbook.service: ConditionFirstBoot is never true in "
                f"this image, so it now runs once and marks {PLAYBOOK_DONE_MARKER}"
            )

        # A share mounted over a system directory does not announce itself. It
        # hides what the image put there and surfaces later as something that
        # looks unrelated, so refuse it and say what it would have cost. A
        # rejected share is recoverable; a machine whose /usr is gone is not.
        if name.endswith('.mount'):
            target = mount_unit_target(contents)
            if target in FORBIDDEN_MOUNT_TARGETS:
                logger.error(
                    f"Refusing mount unit '{name}': it would mount over '{target}', "
                    f"hiding everything the image provides there"
                )
                return

        # Write unit file if contents provided
        if contents:
            unit_path = Path(f'/etc/systemd/system/{name}')
            logger.info(f"Creating systemd unit '{name}'")

            try:
                with open(unit_path, 'w') as f:
                    f.write(contents)
                unit_path.chmod(0o644)
                logger.info(f"Wrote systemd unit '{name}'")
            except Exception as e:
                logger.error(f"Failed to write systemd unit '{name}': {e}", exc_info=True)
                return

        # Write dropins if provided
        if dropins:
            dropin_dir = Path(f'/etc/systemd/system/{name}.d')
            logger.info(f"Creating dropin directory '{dropin_dir}'")

            try:
                dropin_dir.mkdir(parents=True, exist_ok=True)
                dropin_dir.chmod(0o755)

                for dropin in dropins:
                    dropin_name = dropin.get('name')
                    dropin_contents = dropin.get('contents')

                    if not dropin_name or not dropin_contents:
                        logger.warning(f"Dropin for '{name}' missing name or contents")
                        continue

                    dropin_path = dropin_dir / dropin_name
                    logger.info(f"Creating dropin '{dropin_path}'")

                    with open(dropin_path, 'w') as f:
                        f.write(dropin_contents)
                    dropin_path.chmod(0o644)
                    logger.info(f"Wrote dropin '{dropin_path}'")

            except Exception as e:
                logger.error(f"Failed to write dropins for '{name}': {e}", exc_info=True)
                return

        # Reload systemd
        try:
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
            logger.info(f"Systemd daemon reloaded after processing '{name}'")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload systemd: {e.stderr.decode()}")

        # Enable unit if requested
        if enabled:
            try:
                subprocess.run(['systemctl', 'enable', name], check=True, capture_output=True)
                logger.info(f"Enabled systemd unit '{name}'")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to enable systemd unit '{name}': {e.stderr.decode()}")

        # Start mount units immediately (they need to be started, not just enabled)
        if name.endswith('.mount'):
            try:
                logger.info(f"Starting mount unit '{name}'")
                subprocess.run(['systemctl', 'start', name], check=True, capture_output=True, timeout=30)
                logger.info(f"Started mount unit '{name}'")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to start mount unit '{name}': {e.stderr.decode()}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout starting mount unit '{name}'")

        # Start rosetta-activation.service immediately to set up x86_64 binary translation
        # This must run before any containers are started to register the binfmt handler
        if name == 'rosetta-activation.service' and enabled:
            try:
                logger.info(f"Starting rosetta-activation.service for x86_64 translation")
                subprocess.run(['systemctl', 'start', name], check=True, capture_output=True, timeout=30)
                logger.info(f"Started rosetta-activation.service")
            except subprocess.CalledProcessError as e:
                # Not critical - may fail if rosetta virtiofs not available
                logger.warning(f"Rosetta activation failed (may not be available): {e.stderr.decode()}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout starting rosetta-activation.service")

    def extract_hostname_from_config(self, config: Dict[str, Any]) -> Optional[str]:
        """
        Extract hostname from Ignition config.

        Args:
            config: Ignition configuration dict

        Returns:
            Hostname string or None
        """
        storage = config.get('storage', {})
        files = storage.get('files', [])

        for file_config in files:
            if file_config.get('path') == '/etc/hostname':
                contents = file_config.get('contents', {})
                source = contents.get('source', '')

                # Decode data: URI
                if source.startswith('data:'):
                    try:
                        parts = source.split(',', 1)
                        if len(parts) == 2:
                            data = parts[1]
                            # Check if base64 encoded
                            if 'base64' in parts[0]:
                                hostname = base64.b64decode(data).decode('utf-8').strip()
                            else:
                                hostname = data.strip()

                            logger.info(f"Extracted hostname from Ignition config: {hostname}")
                            return hostname
                    except Exception as e:
                        logger.error(f"Failed to decode hostname: {e}")

        return None

    def set_enhanced_hostname(self, config: Dict[str, Any]) -> None:
        """
        Set the hostname to <machine-name>-podman.

        The machine name comes from the /etc/hostname podman puts in the config.
        The suffix keeps the VM distinguishable from the Mac it runs on.
        """
        machine_name = self.extract_hostname_from_config(config)

        if not machine_name:
            logger.warning("No hostname found in Ignition config, keeping default")
            return

        # Sanitize hostname (max 63 chars per label, alphanumeric + dash)
        enhanced_hostname = f"{machine_name}-podman"
        enhanced_hostname = ''.join(c if c.isalnum() or c == '-' else '-'
                                    for c in enhanced_hostname)
        enhanced_hostname = enhanced_hostname[:63].strip('-')

        logger.info(f"Setting enhanced hostname: {enhanced_hostname}")

        try:
            with open('/etc/hostname', 'w') as f:
                f.write(f"{enhanced_hostname}\n")

            subprocess.run(['hostname', enhanced_hostname], check=True, capture_output=True)
            logger.info(f"Enhanced hostname set successfully: {enhanced_hostname}")

        except Exception as e:
            logger.error(f"Failed to set enhanced hostname: {e}", exc_info=True)

    def configure_sentinelone(self, config: Dict[str, Any]) -> None:
        """
        Register a SentinelOne agent baked into the image, if there is one.

        Deployments install the agent afterwards with deploy.sh, which registers
        it itself; this only matters for an image built with the agent inside.

        There used to be more here - a customer ID from a /etc/host-info file
        nothing ever wrote, an /etc/sentinelone/config.json nothing ever read,
        and a "sentinelctl config set customer_id" logged as done whether or not
        it was. Removed rather than kept as a promise the code did not keep.
        """
        sentinelctl_path = '/opt/sentinelone/bin/sentinelctl'
        if not os.path.exists(sentinelctl_path):
            logger.info("SentinelOne not installed, skipping configuration")
            return

        self.register_sentinelone_agent(sentinelctl_path)

    def register_sentinelone_agent(self, sentinelctl_path: str) -> None:
        """
        Register SentinelOne agent with management console using token.

        Checks for registration token in:
        1. /etc/sentinelone/registration-token (created by build script)
        2. Environment variable SENTINELONE_TOKEN

        Args:
            sentinelctl_path: Path to sentinelctl binary
        """
        # Check for registration token
        token = None
        token_file = '/etc/sentinelone/registration-token'

        if os.path.exists(token_file):
            try:
                with open(token_file, 'r') as f:
                    token = f.read().strip()
                logger.info("Found SentinelOne registration token file")
            except Exception as e:
                logger.warning(f"Failed to read registration token: {e}")

        if not token:
            token = os.environ.get('SENTINELONE_TOKEN')
            if token:
                logger.info("Found SentinelOne registration token in environment")

        if not token:
            logger.info("No SentinelOne registration token provided - agent will not register")
            logger.info("To register later, run: sentinelctl management token set <token>")
            return

        # Register agent
        logger.info("Registering SentinelOne agent with management console...")
        try:
            # Set management token
            subprocess.run(
                [sentinelctl_path, 'management', 'token', 'set', token],
                check=True,
                capture_output=True,
                timeout=30
            )
            logger.info("Management token set successfully")

            # Connect to management console
            result = subprocess.run(
                [sentinelctl_path, 'management', 'connect'],
                check=True,
                capture_output=True,
                timeout=60
            )
            logger.info("SentinelOne agent registered successfully!")
            logger.info(f"Registration output: {result.stdout.decode().strip()}")

            # Clean up token file for security
            if os.path.exists(token_file):
                os.remove(token_file)
                logger.info("Removed registration token file")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to register SentinelOne agent: {e.stderr.decode()}")
            logger.error("Agent installed but not registered - manual registration required")
        except subprocess.TimeoutExpired:
            logger.error("SentinelOne registration timed out")
        except Exception as e:
            logger.error(f"Unexpected error during SentinelOne registration: {e}", exc_info=True)

    def apply_config(self, config: Dict[str, Any]) -> None:
        """
        Apply Ignition configuration.

        Args:
            config: Ignition configuration dict
        """
        logger.info("Applying Ignition configuration")

        # First, set enhanced hostname (before creating users/files)
        self.set_enhanced_hostname(config)

        # Create users
        passwd = config.get('passwd', {})
        users = passwd.get('users', [])
        for user in users:
            self.create_user(user)

        # Create storage resources
        storage = config.get('storage', {})

        # Create directories first
        directories = storage.get('directories', [])
        for dir_config in directories:
            self.create_directory(dir_config)

        # Create files
        files = storage.get('files', [])
        for file_config in files:
            # Skip /etc/hostname - already processed by set_enhanced_hostname()
            if file_config.get('path') == '/etc/hostname':
                logger.info("Skipping /etc/hostname (already enhanced)")
                continue
            self.create_file(file_config)

        # Create symlinks
        links = storage.get('links', [])
        for link_config in links:
            self.create_link(link_config)

        # Enable systemd units
        systemd = config.get('systemd', {})
        units = systemd.get('units', [])
        for unit in units:
            self.enable_systemd_unit(unit)

        # Setup registries.conf.d symlink to host (after mounts are up)
        self.setup_registries_conf_symlink(config)

        # Configure SentinelOne (after everything else)
        self.configure_sentinelone(config)

        logger.info("Ignition configuration applied successfully")

    @staticmethod
    def find_host_home(machine_name: Optional[str], users_root: Path = Path('/Users')) -> Optional[Path]:
        """
        The home of the Mac user this machine belongs to, as seen over /Users.

        Every home on the Mac is visible there, so "the first directory that
        looks like a home" can be someone else's. The owner is the one whose
        podman configuration defines a machine of this name.
        """
        if not machine_name or not users_root.is_dir():
            return None
        candidates = []
        try:
            entries = sorted(users_root.iterdir())
        except OSError:
            return None
        for entry in entries:
            if entry.name.startswith('.') or entry.name == 'Shared':
                continue
            machine_dir = entry / '.config' / 'containers' / 'podman' / 'machine'
            try:
                if any(machine_dir.glob(f'*/{machine_name}.json')):
                    candidates.append(entry)
            except OSError:
                continue  # someone else's home, not readable - not ours
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            logger.warning(
                f"Machine '{machine_name}' is defined in several homes "
                f"({', '.join(str(c) for c in candidates)}); not guessing"
            )
        return None

    def setup_registries_conf_symlink(self, config: Dict[str, Any]) -> None:
        """
        Make the host's registries.conf apply in the VM, the way Podman Desktop
        expects: a symlink in /etc/containers/registries.conf.d pointing at the
        host user's ~/.config/containers/registries.conf over the /Users mount.

        Nothing is written on the host. This used to create the host's
        registries.conf when it was missing and fill it with four search
        registries; the VM's business is to read the host's configuration, not
        to author it. Without a host file there is no symlink either - a
        dangling one in registries.conf.d breaks every podman command.

        Unqualified names resolve against docker.io only. Searching several
        registries for a short name lets whichever answers first supply the
        image, which is how short-name squatting works.
        """
        logger.info("Setting up registry configuration")
        vm_registries_dir = Path('/etc/containers/registries.conf.d')

        try:
            vm_registries_dir.mkdir(parents=True, exist_ok=True)

            default_search_conf = vm_registries_dir / '00-unqualified-search.conf'
            if not default_search_conf.exists():
                default_search_conf.write_text('unqualified-search-registries = ["docker.io"]\n')
                logger.info(f"Created default search registries config: {default_search_conf}")

            host_home = self.find_host_home(self.extract_hostname_from_config(config))
            if not host_home:
                logger.warning("Host home not identified - the host's registries.conf is not linked")
                return

            host_registries_conf = host_home / '.config' / 'containers' / 'registries.conf'
            if not host_registries_conf.is_file():
                logger.info(f"No {host_registries_conf} on the host - nothing to link")
                return

            symlink_path = vm_registries_dir / '999-podman-desktop.conf'
            if symlink_path.is_symlink() and os.readlink(symlink_path) == str(host_registries_conf):
                logger.info(f"Symlink already correct: {symlink_path}")
                return
            if os.path.lexists(symlink_path):
                symlink_path.unlink()
            symlink_path.symlink_to(host_registries_conf)
            logger.info(f"Created symlink: {symlink_path} -> {host_registries_conf}")

        except Exception as e:
            logger.error(f"Failed to setup registry configuration: {e}", exc_info=True)

    def run(self) -> int:
        """
        Main entry point - fetch and apply Ignition config.

        Returns:
            Exit code (0 = success, 1 = failure)
        """
        logger.info("=== Ignition Provider Starting ===")

        # Fetch config
        config = self.fetch_config_from_vsock()

        if config is None:
            logger.error("FATAL: No Ignition config available")
            logger.error("Machine cannot start without proper configuration")
            return 1

        # Apply config
        try:
            self.apply_config(config)
            logger.info("=== Ignition Provider Completed Successfully ===")
            return 0
        except Exception as e:
            logger.error(f"Failed to apply Ignition config: {e}", exc_info=True)
            return 1


def main():
    """Main entry point."""
    provider = IgnitionProvider()
    exit_code = provider.run()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
