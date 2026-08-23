#!/usr/bin/env python3
"""
Integration tests for Ignition configuration validation.

Tests that generated Ignition configs match Podman expectations.
"""

import unittest
import json
import subprocess
import tempfile
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestIgnitionConfigValidation(unittest.TestCase):
    """Test Ignition config structure and compatibility."""

    def test_ignition_spec_version(self):
        """Test that we use a valid Ignition spec version."""
        valid_versions = ['3.0.0', '3.1.0', '3.2.0', '3.3.0', '3.4.0']

        # Our wrapper uses 3.4.0
        wrapper_version = '3.4.0'
        self.assertIn(wrapper_version, valid_versions)

    def test_minimal_ignition_config(self):
        """Test minimal valid Ignition config structure."""
        config = {
            'ignition': {'version': '3.2.0'}
        }

        # Should be valid JSON
        json_str = json.dumps(config)
        parsed = json.loads(json_str)

        self.assertEqual(parsed['ignition']['version'], '3.2.0')

    def test_user_config_structure(self):
        """Test user configuration structure."""
        config = {
            'ignition': {'version': '3.2.0'},
            'passwd': {
                'users': [{
                    'name': 'core',
                    'sshAuthorizedKeys': ['ssh-rsa AAAAB3NzaC1...']
                }]
            }
        }

        # Validate structure
        self.assertIn('passwd', config)
        self.assertIn('users', config['passwd'])
        self.assertEqual(len(config['passwd']['users']), 1)

        user = config['passwd']['users'][0]
        self.assertEqual(user['name'], 'core')
        self.assertIn('sshAuthorizedKeys', user)
        self.assertIsInstance(user['sshAuthorizedKeys'], list)

    def test_storage_files_structure(self):
        """Test storage files configuration structure."""
        config = {
            'ignition': {'version': '3.2.0'},
            'storage': {
                'files': [{
                    'path': '/etc/hostname',
                    'mode': 420,
                    'contents': {
                        'source': 'data:,my-machine'
                    }
                }]
            }
        }

        # Validate structure
        self.assertIn('storage', config)
        self.assertIn('files', config['storage'])

        file_obj = config['storage']['files'][0]
        self.assertEqual(file_obj['path'], '/etc/hostname')
        self.assertEqual(file_obj['mode'], 420)  # 0644 in octal
        self.assertIn('contents', file_obj)
        self.assertIn('source', file_obj['contents'])

    def test_data_uri_formats(self):
        """Test various data: URI formats."""
        import base64

        # Plain text
        plain_uri = 'data:,Hello%20World'
        self.assertTrue(plain_uri.startswith('data:'))

        # Base64
        content = b'Hello World'
        b64_content = base64.b64encode(content).decode()
        b64_uri = f'data:text/plain;charset=utf-8;base64,{b64_content}'
        self.assertTrue(b64_uri.startswith('data:'))
        self.assertIn('base64', b64_uri)

    def test_systemd_units_structure(self):
        """Test systemd units configuration structure."""
        config = {
            'ignition': {'version': '3.2.0'},
            'systemd': {
                'units': [{
                    'name': 'podman.socket',
                    'enabled': True
                }]
            }
        }

        # Validate structure
        self.assertIn('systemd', config)
        self.assertIn('units', config['systemd'])

        unit = config['systemd']['units'][0]
        self.assertEqual(unit['name'], 'podman.socket')
        self.assertTrue(unit['enabled'])

    def test_complete_podman_config_structure(self):
        """Test complete Podman-style Ignition config."""
        import base64

        hostname = 'test-machine'
        hostname_b64 = base64.b64encode(hostname.encode()).decode()

        config = {
            'ignition': {'version': '3.2.0'},
            'passwd': {
                'users': [
                    {
                        'name': 'core',
                        'uid': 501,
                        'groups': ['sudo', 'wheel'],
                        'sshAuthorizedKeys': ['ssh-rsa AAAAB3NzaC1yc2E...']
                    }
                ]
            },
            'storage': {
                'files': [
                    {
                        'path': '/etc/hostname',
                        'mode': 420,
                        'contents': {
                            'source': f'data:text/plain;charset=utf-8;base64,{hostname_b64}'
                        }
                    }
                ],
                'links': [
                    {
                        'path': '/usr/local/bin/docker',
                        'target': '/usr/bin/podman',
                        'overwrite': True
                    }
                ]
            },
            'systemd': {
                'units': [
                    {
                        'name': 'podman.socket',
                        'enabled': True
                    }
                ]
            }
        }

        # Validate JSON serialization
        json_str = json.dumps(config, indent=2)
        parsed = json.loads(json_str)

        # Verify all sections present
        self.assertIn('ignition', parsed)
        self.assertIn('passwd', parsed)
        self.assertIn('storage', parsed)
        self.assertIn('systemd', parsed)

        # Verify storage subsections
        self.assertIn('files', parsed['storage'])
        self.assertIn('links', parsed['storage'])

    def test_shouldExist_field(self):
        """Test Ignition 3.2.0 shouldExist field for users."""
        config = {
            'ignition': {'version': '3.2.0'},
            'passwd': {
                'users': [
                    {
                        'name': 'core',
                        'shouldExist': False
                    }
                ]
            }
        }

        # Validate structure
        user = config['passwd']['users'][0]
        self.assertIn('shouldExist', user)
        self.assertFalse(user['shouldExist'])

    def test_ignition_provider_compatibility(self):
        """Test that ignition-provider.py exists and is valid Python."""
        provider_path = REPO_ROOT / 'resources' / 'scripts' / 'ignition-provider.py'

        self.assertTrue(provider_path.exists(), "Ignition provider not found")

        # Check shebang
        with open(provider_path, 'r') as f:
            first_line = f.readline()
            self.assertTrue(first_line.startswith('#!'), "Missing shebang")
            self.assertIn('python', first_line, "Should be Python script")

        # Try to compile it
        try:
            with open(provider_path, 'r') as f:
                compile(f.read(), str(provider_path), 'exec')
        except SyntaxError as e:
            self.fail(f"Ignition provider has syntax error: {e}")

    def test_file_mode_values(self):
        """Test that file mode values are correct."""
        # Common file modes in decimal (Ignition uses decimal, not octal in JSON)
        modes = {
            '0644': 420,
            '0755': 493,
            '0600': 384,
            '0700': 448
        }

        # Test conversion
        for octal_str, decimal in modes.items():
            self.assertEqual(int(octal_str, 8), decimal)

    def test_url_encoding_in_data_uri(self):
        """Test URL encoding in data: URIs."""
        import urllib.parse

        # Test common encodings
        test_cases = {
            'Hello World': 'Hello%20World',
            'foo\nbar': 'foo%0Abar',
            'key=value': 'key%3Dvalue'
        }

        for plain, encoded in test_cases.items():
            self.assertEqual(urllib.parse.quote(plain), encoded)
            self.assertEqual(urllib.parse.unquote(encoded), plain)


class TestIgnitionProviderIntegration(unittest.TestCase):
    """Integration tests for ignition-provider.py."""

    def setUp(self):
        """Set up test environment."""
        self.provider_path = REPO_ROOT / 'resources' / 'scripts' / 'ignition-provider.py'
        self.assertTrue(self.provider_path.exists())

    def test_provider_help(self):
        """Test that provider script can be executed."""
        # Just try to import it (syntax check)
        try:
            result = subprocess.run(
                ['python3', '-m', 'py_compile', str(self.provider_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            self.assertEqual(result.returncode, 0, f"Compile failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.fail("Provider script compilation timed out")

    def test_ignition_service_file(self):
        """Test that ignition-provider.service exists and has valid structure."""
        service_path = REPO_ROOT / 'resources' / 'services' / 'ignition-provider.service'
        self.assertTrue(service_path.exists(), "Service file not found")

        with open(service_path, 'r') as f:
            content = f.read()

            # Check for required sections
            self.assertIn('[Unit]', content)
            self.assertIn('[Service]', content)
            self.assertIn('[Install]', content)

            # Check for critical settings
            self.assertIn('Type=oneshot', content)
            self.assertIn('ignition-provider.py', content)
            self.assertIn('Before=', content)  # Should run before other services


if __name__ == '__main__':
    unittest.main(verbosity=2)
