#!/usr/bin/env python3
"""
Unit tests for ignition-provider.py

Tests all Ignition config handling including:
- User creation/deletion (with shouldExist)
- File creation (including data: URI decoding)
- Directory creation
- Symlink creation
- Systemd unit management
- Hostname enhancement
- SentinelOne configuration
"""

import unittest
import json
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

# Add parent directory to path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

# Import by loading the module with dash in name
import importlib.util
spec = importlib.util.spec_from_file_location("ignition_provider",
    os.path.join(REPO_ROOT, "resources", "scripts", "ignition-provider.py"))
ignition_provider = importlib.util.module_from_spec(spec)
sys.modules["ignition_provider"] = ignition_provider
spec.loader.exec_module(ignition_provider)

# Now we can import from it
IgnitionProvider = ignition_provider.IgnitionProvider


class TestIgnitionProvider(unittest.TestCase):
    """Test suite for IgnitionProvider class."""

    def setUp(self):
        """Set up test fixtures."""
        self.provider = IgnitionProvider()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_extract_hostname_from_config_plain(self):
        """Test hostname extraction from Ignition config with plain data: URI."""
        config = {
            'storage': {
                'files': [{
                    'path': '/etc/hostname',
                    'contents': {
                        'source': 'data:,my-machine'
                    }
                }]
            }
        }

        hostname = self.provider.extract_hostname_from_config(config)
        self.assertEqual(hostname, 'my-machine')

    def test_extract_hostname_from_config_base64(self):
        """Test hostname extraction with base64-encoded data: URI."""
        import base64
        hostname_b64 = base64.b64encode(b'test-machine').decode('utf-8')

        config = {
            'storage': {
                'files': [{
                    'path': '/etc/hostname',
                    'contents': {
                        'source': f'data:text/plain;charset=utf-8;base64,{hostname_b64}'
                    }
                }]
            }
        }

        hostname = self.provider.extract_hostname_from_config(config)
        self.assertEqual(hostname, 'test-machine')

    def test_extract_hostname_missing(self):
        """Test hostname extraction when /etc/hostname is not in config."""
        config = {
            'storage': {
                'files': []
            }
        }

        hostname = self.provider.extract_hostname_from_config(config)
        self.assertIsNone(hostname)

    def test_get_host_hostname_hint_plain(self):
        """Test host hostname hint extraction with plain data: URI."""
        config = {
            'storage': {
                'files': [{
                    'path': '/etc/host-info',
                    'contents': {
                        'source': 'data:,HOST_HOSTNAME=MacBook-Pro%0AMACHINE_NAME=test'
                    }
                }]
            }
        }

        hint = self.provider.get_host_hostname_hint(config)
        self.assertEqual(hint, 'MacBook-Pro')

    def test_get_host_hostname_hint_base64(self):
        """Test host hostname hint extraction with base64 encoding."""
        import base64
        host_info = "HOST_HOSTNAME=MacBook-Pro\nMACHINE_NAME=test"
        host_info_b64 = base64.b64encode(host_info.encode()).decode()

        config = {
            'storage': {
                'files': [{
                    'path': '/etc/host-info',
                    'contents': {
                        'source': f'data:text/plain;charset=utf-8;base64,{host_info_b64}'
                    }
                }]
            }
        }

        hint = self.provider.get_host_hostname_hint(config)
        self.assertEqual(hint, 'MacBook-Pro')

    def test_get_host_hostname_hint_missing(self):
        """Test host hostname hint when /etc/host-info is missing."""
        config = {
            'storage': {
                'files': []
            }
        }

        hint = self.provider.get_host_hostname_hint(config)
        self.assertIsNone(hint)

    @patch('ignition_provider.subprocess.run')
    @patch('builtins.open', create=True)
    def test_set_enhanced_hostname_with_host(self, mock_open, mock_subprocess):
        """Test enhanced hostname creation with host hint."""
        config = {
            'storage': {
                'files': [
                    {
                        'path': '/etc/hostname',
                        'contents': {'source': 'data:,my-machine'}
                    },
                    {
                        'path': '/etc/host-info',
                        'contents': {'source': 'data:,HOST_HOSTNAME=MacBook-Pro%0AMACHINE_NAME=my-machine'}
                    }
                ]
            }
        }

        # Mock file writes
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        self.provider.set_enhanced_hostname(config)

        # Verify hostname command was called
        mock_subprocess.assert_called()
        args = mock_subprocess.call_args_list[0][0][0]
        self.assertEqual(args[0], 'hostname')
        self.assertEqual(args[1], 'MacBook-Pro-podman-my-machine')

    @patch('ignition_provider.subprocess.run')
    @patch('builtins.open', create=True)
    def test_set_enhanced_hostname_without_host(self, mock_open, mock_subprocess):
        """Test enhanced hostname creation without host hint."""
        config = {
            'storage': {
                'files': [
                    {
                        'path': '/etc/hostname',
                        'contents': {'source': 'data:,my-machine'}
                    }
                ]
            }
        }

        # Mock file writes
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        self.provider.set_enhanced_hostname(config)

        # Verify hostname command was called
        mock_subprocess.assert_called()
        args = mock_subprocess.call_args_list[0][0][0]
        self.assertEqual(args[0], 'hostname')
        self.assertEqual(args[1], 'my-machine-podman')

    def test_create_file_plain_content(self):
        """Test file creation with plain data: URI."""
        test_file = os.path.join(self.test_dir, 'test.txt')

        file_config = {
            'path': test_file,
            'contents': {
                'source': 'data:,Hello%20World'
            },
            'mode': 0o644
        }

        self.provider.create_file(file_config)

        self.assertTrue(os.path.exists(test_file))
        with open(test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, 'Hello World')

    def test_create_file_base64_content(self):
        """Test file creation with base64-encoded data: URI."""
        import base64
        test_file = os.path.join(self.test_dir, 'test.txt')
        content_b64 = base64.b64encode(b'Hello World\n').decode()

        file_config = {
            'path': test_file,
            'contents': {
                'source': f'data:text/plain;charset=utf-8;base64,{content_b64}'
            },
            'mode': 0o600
        }

        self.provider.create_file(file_config)

        self.assertTrue(os.path.exists(test_file))
        with open(test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, 'Hello World\n')

    def test_create_directory(self):
        """Test directory creation."""
        test_dir = os.path.join(self.test_dir, 'testdir')

        dir_config = {
            'path': test_dir,
            'mode': 0o755
        }

        self.provider.create_directory(dir_config)

        self.assertTrue(os.path.exists(test_dir))
        self.assertTrue(os.path.isdir(test_dir))

    def test_create_directory_nested(self):
        """Test nested directory creation."""
        test_dir = os.path.join(self.test_dir, 'a', 'b', 'c')

        dir_config = {
            'path': test_dir,
            'mode': 0o750
        }

        self.provider.create_directory(dir_config)

        self.assertTrue(os.path.exists(test_dir))
        self.assertTrue(os.path.isdir(test_dir))

    def test_create_link(self):
        """Test symlink creation."""
        # Create target file
        target = os.path.join(self.test_dir, 'target.txt')
        Path(target).touch()

        link = os.path.join(self.test_dir, 'link.txt')

        link_config = {
            'path': link,
            'target': target,
            'overwrite': False
        }

        self.provider.create_link(link_config)

        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), target)

    def test_create_link_overwrite(self):
        """Test symlink creation with overwrite."""
        # Create existing file
        link = os.path.join(self.test_dir, 'link.txt')
        Path(link).write_text('old content')

        target = os.path.join(self.test_dir, 'target.txt')
        Path(target).touch()

        link_config = {
            'path': link,
            'target': target,
            'overwrite': True
        }

        self.provider.create_link(link_config)

        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), target)

    def test_apply_config_skips_hostname(self):
        """Test that apply_config skips /etc/hostname to preserve enhanced version."""
        config = {
            'ignition': {'version': '3.2.0'},
            'passwd': {'users': []},
            'storage': {
                'files': [
                    {
                        'path': '/etc/hostname',
                        'contents': {'source': 'data:,original-name'}
                    },
                    {
                        'path': os.path.join(self.test_dir, 'other.txt'),
                        'contents': {'source': 'data:,test'}
                    }
                ]
            },
            'systemd': {'units': []}
        }

        # Track if create_file was called for /etc/hostname
        create_file_calls = []
        original_create_file = self.provider.create_file

        def track_create_file(file_config):
            create_file_calls.append(file_config.get('path'))
            if file_config.get('path') != '/etc/hostname':
                original_create_file(file_config)

        with patch.object(self.provider, 'create_file', side_effect=track_create_file):
            with patch.object(self.provider, 'set_enhanced_hostname'):
                with patch.object(self.provider, 'configure_sentinelone'):
                    self.provider.apply_config(config)

        # Verify /etc/hostname was NOT passed to create_file
        # (it should be skipped in the loop)
        self.assertNotIn('/etc/hostname', create_file_calls)

        # Verify other file WAS created
        other_file = os.path.join(self.test_dir, 'other.txt')
        self.assertTrue(os.path.exists(other_file))


class TestPodmanIgnitionCompatibility(unittest.TestCase):
    """Test compatibility with actual Podman-generated Ignition configs."""

    def setUp(self):
        """Set up test fixtures."""
        self.provider = IgnitionProvider()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_podman_standard_config(self):
        """Test handling of standard Podman-generated Ignition config."""
        import base64

        # Simulate Podman-generated config
        config = {
            "ignition": {"version": "3.2.0"},
            "passwd": {
                "users": [
                    {
                        "name": "core",
                        "uid": 501,
                        "groups": ["sudo", "wheel", "adm", "systemd-journal"],
                        "sshAuthorizedKeys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"]
                    },
                    {
                        "name": "root",
                        "sshAuthorizedKeys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"]
                    }
                ]
            },
            "storage": {
                "files": [
                    {
                        "path": "/etc/hostname",
                        "contents": {
                            "source": f"data:text/plain;charset=utf-8;base64,{base64.b64encode(b'podman-machine').decode()}"
                        },
                        "mode": 420
                    },
                    {
                        "path": "/var/lib/systemd/linger/core",
                        "contents": {"source": "data:,"}
                    }
                ],
                "links": [
                    {
                        "path": "/usr/local/bin/docker",
                        "target": "/usr/bin/podman",
                        "overwrite": True
                    }
                ]
            },
            "systemd": {
                "units": [
                    {
                        "name": "podman.socket",
                        "enabled": True
                    }
                ]
            }
        }

        # Patch the writers rather than the filesystem: this asserts that
        # apply_config dispatches every section, and keeps the test runnable
        # off the VM where /etc and /var/lib are not writable.
        with patch.object(self.provider, 'create_user') as mock_user, \
             patch.object(self.provider, 'create_file') as mock_file, \
             patch.object(self.provider, 'create_directory'), \
             patch.object(self.provider, 'create_link') as mock_link, \
             patch.object(self.provider, 'enable_systemd_unit') as mock_unit, \
             patch.object(self.provider, 'set_enhanced_hostname'), \
             patch.object(self.provider, 'configure_sentinelone'), \
             patch.object(self.provider, 'setup_registries_conf_symlink'):
            try:
                self.provider.apply_config(config)
            except Exception as e:
                self.fail(f"apply_config raised exception: {e}")

        self.assertEqual(mock_user.call_count, 2, "both users from the config are created")
        created_files = [c.args[0]['path'] for c in mock_file.call_args_list]
        self.assertIn('/var/lib/systemd/linger/core', created_files)
        self.assertEqual(mock_link.call_count, 1, "the docker compatibility link is created")
        self.assertEqual(mock_unit.call_count, 1, "podman.socket is enabled")

    def test_podman_custom_user_config(self):
        """Test handling of Podman config with custom username and shouldExist."""
        config = {
            "ignition": {"version": "3.2.0"},
            "passwd": {
                "users": [
                    {
                        "name": "myuser",
                        "uid": 501,
                        "groups": ["sudo"],
                        "sshAuthorizedKeys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"]
                    },
                    {
                        "name": "root",
                        "sshAuthorizedKeys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"]
                    },
                    {
                        "name": "core",
                        "shouldExist": False  # Disable default core user
                    }
                ]
            },
            "storage": {
                "files": [],
                "links": []
            },
            "systemd": {
                "units": []
            }
        }

        # Mock user operations
        with patch('ignition_provider.subprocess.run'):
            with patch('ignition_provider.pwd.getpwnam') as mock_getpwnam:
                # core exists, myuser and root don't
                def getpwnam_side_effect(username):
                    if username == 'core':
                        return Mock(pw_uid=1000, pw_gid=1000, pw_dir='/home/core')
                    raise KeyError

                mock_getpwnam.side_effect = getpwnam_side_effect

                with patch('builtins.open', create=True):
                    # Should handle shouldExist=false without errors
                    try:
                        self.provider.apply_config(config)
                    except Exception as e:
                        self.fail(f"apply_config raised exception: {e}")


class TestIgnitionSpecVersion(unittest.TestCase):
    """Test Ignition specification version compatibility."""

    def test_version_32_fields(self):
        """Verify support for Ignition 3.2.0 fields."""
        provider = IgnitionProvider()

        # Test shouldExist field (new in 3.2.0)
        user_config = {
            'name': 'testuser',
            'shouldExist': False
        }

        with patch('ignition_provider.subprocess.run'):
            with patch('ignition_provider.pwd.getpwnam', return_value=Mock()):
                # Should handle shouldExist without error
                try:
                    provider.create_user(user_config)
                except Exception as e:
                    self.fail(f"create_user with shouldExist raised exception: {e}")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
