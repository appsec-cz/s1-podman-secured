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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/ignition-provider.log')
    ]
)
logger = logging.getLogger('ignition-provider')

# Vsock constants
VMADDR_CID_HOST = 2  # Host CID in vsock
IGNITION_VSOCK_PORT = 1024  # Port where vfkit serves Ignition config


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
                body_bytes = b""
                while True:
                    # Read chunk size line
                    size_line = b""
                    while not size_line.endswith(b"\r\n"):
                        byte = sock.recv(1)
                        if not byte:
                            break
                        size_line += byte

                    chunk_size = int(size_line.strip(), 16)
                    if chunk_size == 0:
                        # Read trailing CRLF
                        sock.recv(2)
                        break

                    # Read chunk data
                    chunk_data = b""
                    while len(chunk_data) < chunk_size:
                        remaining = chunk_size - len(chunk_data)
                        chunk_data += sock.recv(min(4096, remaining))
                    body_bytes += chunk_data

                    # Read trailing CRLF after chunk
                    sock.recv(2)

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

            # Remove existing link/file if overwrite is true
            if overwrite and link_path.exists():
                if link_path.is_symlink() or link_path.is_file():
                    link_path.unlink()
                elif link_path.is_dir():
                    import shutil
                    shutil.rmtree(link_path)

            # Create symlink
            if not link_path.exists():
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

        enabled = unit_config.get('enabled', False)
        contents = unit_config.get('contents')
        dropins = unit_config.get('dropins', [])

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

    def get_host_hostname_hint(self, config: Dict[str, Any]) -> Optional[str]:
        """
        Try to extract host hostname hint from Ignition config.

        Checks for /etc/host-info file created by podman-machine-init-wrapper.sh
        which contains HOST_HOSTNAME=<hostname>

        Args:
            config: Ignition configuration dict

        Returns:
            Host hostname hint or None
        """
        storage = config.get('storage', {})
        files = storage.get('files', [])

        for file_config in files:
            if file_config.get('path') == '/etc/host-info':
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
                                host_info = base64.b64decode(data).decode('utf-8')
                            else:
                                # URL decode %0A (newline)
                                import urllib.parse
                                host_info = urllib.parse.unquote(data)

                            # Parse HOST_HOSTNAME=value
                            for line in host_info.split('\n'):
                                if line.startswith('HOST_HOSTNAME='):
                                    hostname = line.split('=', 1)[1].strip()
                                    logger.info(f"Extracted host hostname from Ignition: {hostname}")
                                    return hostname
                    except Exception as e:
                        logger.error(f"Failed to decode host-info: {e}")

        return None

    def set_enhanced_hostname(self, config: Dict[str, Any]) -> None:
        """
        Set enhanced hostname with host system information.

        Creates hostname in format: <machine-name>-podman
        Or if host hint available: <host-hint>-podman-<machine-name>

        Args:
            config: Ignition configuration dict
        """
        machine_name = self.extract_hostname_from_config(config)

        if not machine_name:
            logger.warning("No hostname found in Ignition config, keeping default")
            return

        # Try to get host hostname hint
        host_hint = self.get_host_hostname_hint(config)

        if host_hint:
            # Format: <host>-podman-<machine>
            enhanced_hostname = f"{host_hint}-podman-{machine_name}"
        else:
            # Format: <machine>-podman
            enhanced_hostname = f"{machine_name}-podman"

        # Sanitize hostname (max 64 chars, alphanumeric + dash)
        enhanced_hostname = enhanced_hostname[:64]
        enhanced_hostname = ''.join(c if c.isalnum() or c == '-' else '-'
                                    for c in enhanced_hostname)
        enhanced_hostname = enhanced_hostname.strip('-')

        logger.info(f"Setting enhanced hostname: {enhanced_hostname}")

        # Write to /etc/hostname
        try:
            with open('/etc/hostname', 'w') as f:
                f.write(f"{enhanced_hostname}\n")

            # Set hostname immediately
            subprocess.run(['hostname', enhanced_hostname], check=True, capture_output=True)

            logger.info(f"Enhanced hostname set successfully: {enhanced_hostname}")

            # Save for SentinelOne configuration
            with open('/etc/podman-machine-info', 'w') as f:
                f.write(f"MACHINE_NAME={machine_name}\n")
                f.write(f"ENHANCED_HOSTNAME={enhanced_hostname}\n")
                if host_hint:
                    f.write(f"HOST_HINT={host_hint}\n")

        except Exception as e:
            logger.error(f"Failed to set enhanced hostname: {e}", exc_info=True)

    def configure_sentinelone(self, config: Dict[str, Any]) -> None:
        """
        Configure SentinelOne agent with custom identification.

        Sets:
        - Customer ID (from hostname or config)
        - Custom tags for filtering in console

        Args:
            config: Ignition configuration dict
        """
        logger.info("Configuring SentinelOne agent identification")

        # Check if SentinelOne is installed
        sentinelctl_path = '/opt/sentinelone/bin/sentinelctl'
        if not os.path.exists(sentinelctl_path):
            logger.info("SentinelOne not installed, skipping configuration")
            return

        # Read machine info
        machine_name = self.extract_hostname_from_config(config)
        enhanced_hostname = None
        host_hint = None

        if os.path.exists('/etc/podman-machine-info'):
            try:
                with open('/etc/podman-machine-info', 'r') as f:
                    for line in f:
                        if line.startswith('ENHANCED_HOSTNAME='):
                            enhanced_hostname = line.split('=', 1)[1].strip()
                        elif line.startswith('HOST_HINT='):
                            host_hint = line.split('=', 1)[1].strip()
            except Exception as e:
                logger.warning(f"Failed to read machine info: {e}")

        # Set customer ID
        customer_id = host_hint or machine_name or "podman-machine"
        logger.info(f"Setting SentinelOne customer ID: {customer_id}")

        try:
            # Create SentinelOne config file
            s1_config = {
                'customer_id': customer_id,
                'tags': {
                    'podman_machine': 'true',
                    'machine_type': 'podman',
                }
            }

            if machine_name:
                s1_config['tags']['machine_name'] = machine_name

            if host_hint:
                s1_config['tags']['host_system'] = host_hint

            # Write config file for SentinelOne installation
            config_path = '/etc/sentinelone/config.json'
            os.makedirs('/etc/sentinelone', exist_ok=True)

            with open(config_path, 'w') as f:
                json.dump(s1_config, f, indent=2)

            logger.info(f"SentinelOne config written to {config_path}")

            # Try to set customer ID if agent is already installed
            try:
                subprocess.run(
                    [sentinelctl_path, 'config', 'set', 'customer_id', customer_id],
                    check=False,  # Don't fail if command doesn't work
                    capture_output=True,
                    timeout=5
                )
                logger.info("Set SentinelOne customer ID via sentinelctl")
            except Exception as e:
                logger.debug(f"Could not set customer ID via sentinelctl: {e}")

            # Register agent with management console if token is available
            self.register_sentinelone_agent(sentinelctl_path)

        except Exception as e:
            logger.error(f"Failed to configure SentinelOne: {e}", exc_info=True)

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

        # Configure SentinelOne (after everything else)
        self.configure_sentinelone(config)

        logger.info("Ignition configuration applied successfully")

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
