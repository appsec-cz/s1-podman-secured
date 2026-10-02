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

    @patch('ignition_provider.subprocess.run')
    @patch('builtins.open', create=True)
    def test_set_enhanced_hostname_is_a_valid_label(self, mock_open, mock_subprocess):
        """Odd characters become dashes and the result fits one DNS label."""
        config = {'storage': {'files': [{
            'path': '/etc/hostname',
            'contents': {'source': 'data:,' + 'my_machine.' + 'x' * 80},
        }]}}
        mock_open.return_value.__enter__.return_value = MagicMock()

        self.provider.set_enhanced_hostname(config)

        hostname = mock_subprocess.call_args_list[0][0][0][1]
        self.assertTrue(hostname.startswith('my-machine-'))
        self.assertLessEqual(len(hostname), 63)
        self.assertRegex(hostname, r'^[A-Za-z0-9-]+$')

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

    def test_create_link_over_a_dangling_link(self):
        """A dangling link read as absent: not replaced, and symlink_to() failed."""
        link = os.path.join(self.test_dir, 'link')
        os.symlink(os.path.join(self.test_dir, 'gone'), link)
        target = os.path.join(self.test_dir, 'target.txt')
        Path(target).touch()

        self.provider.create_link({'path': link, 'target': target, 'overwrite': True})
        self.assertEqual(os.readlink(link), target)

    def test_create_link_keeps_a_dangling_link_without_overwrite(self):
        link = os.path.join(self.test_dir, 'link')
        dangling = os.path.join(self.test_dir, 'gone')
        os.symlink(dangling, link)

        with self.assertLogs('ignition-provider', level='INFO') as logs:
            self.provider.create_link({'path': link, 'target': '/elsewhere', 'overwrite': False})
        self.assertEqual(os.readlink(link), dangling)
        self.assertFalse(any('ERROR' in line for line in logs.output))

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


class TestHostHome(unittest.TestCase):
    """Which /Users entry is the machine owner's - never just the first one."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root)

    def home(self, name, machines=()):
        h = self.root / name
        (h / 'Library').mkdir(parents=True)
        for m in machines:
            d = h / '.config' / 'containers' / 'podman' / 'machine' / 'applehv'
            d.mkdir(parents=True, exist_ok=True)
            (d / f'{m}.json').write_text('{}')
        return h

    def find(self, machine):
        return IgnitionProvider.find_host_home(machine, self.root)

    def test_the_owner_of_the_machine_is_chosen(self):
        self.home('alice', machines=['other'])
        bob = self.home('bob', machines=['podman-machine-default'])
        self.home('carol')
        self.assertEqual(self.find('podman-machine-default'), bob)

    def test_a_home_without_the_machine_is_never_chosen(self):
        self.home('alice')
        self.assertIsNone(self.find('podman-machine-default'))

    def test_two_owners_is_not_guessed(self):
        self.home('alice', machines=['podman-machine-default'])
        self.home('bob', machines=['podman-machine-default'])
        self.assertIsNone(self.find('podman-machine-default'))

    def test_no_machine_name(self):
        self.home('alice', machines=['x'])
        self.assertIsNone(self.find(None))


class TestRegistriesSetup(unittest.TestCase):
    """The VM reads the host's registry configuration; it never writes it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.users = self.root / 'Users'
        self.vm_dir = self.root / 'etc-registries.conf.d'
        self.home = self.users / 'glux'
        d = self.home / '.config' / 'containers' / 'podman' / 'machine' / 'applehv'
        d.mkdir(parents=True)
        (d / 'm.json').write_text('{}')
        self.config = {'storage': {'files': [
            {'path': '/etc/hostname', 'contents': {'source': 'data:,m'}}]}}

    def tearDown(self):
        shutil.rmtree(self.root)

    def run_setup(self):
        provider = IgnitionProvider()
        real_path = ignition_provider.Path

        def fake_path(p, *rest):
            if str(p) == '/etc/containers/registries.conf.d':
                return real_path(self.vm_dir)
            return real_path(p, *rest)

        real_find = IgnitionProvider.find_host_home
        with patch.object(ignition_provider, 'Path', side_effect=fake_path), \
             patch.object(IgnitionProvider, 'find_host_home',
                          side_effect=lambda name: real_find(name, self.users)):
            provider.setup_registries_conf_symlink(self.config)

    def test_search_is_docker_io_only(self):
        self.run_setup()
        conf = (self.vm_dir / '00-unqualified-search.conf').read_text()
        self.assertIn('["docker.io"]', conf)
        self.assertNotIn('quay.io', conf)

    def test_nothing_is_written_on_the_host(self):
        self.run_setup()
        self.assertFalse((self.home / '.config' / 'containers' / 'registries.conf').exists())
        self.assertFalse((self.vm_dir / '999-podman-desktop.conf').is_symlink(),
                         "no dangling symlink to a host file that does not exist")

    def test_an_existing_host_file_is_linked(self):
        host_conf = self.home / '.config' / 'containers' / 'registries.conf'
        host_conf.write_text('# host\n')
        self.run_setup()
        link = self.vm_dir / '999-podman-desktop.conf'
        self.assertEqual(os.readlink(link), str(host_conf))
        self.assertEqual(host_conf.read_text(), '# host\n')


class FakeSocket:
    """A socket that hands out its data in the given pieces, then b'' for ever."""

    def __init__(self, *pieces):
        self.buffer = b"".join(pieces)
        self.reads = 0

    def recv(self, n):
        self.reads += 1
        if self.reads > 100000:
            raise AssertionError("still reading from a closed connection")
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data


class TestChunkedBody(unittest.TestCase):
    """The chunked reader once spun for ever on a host that closed mid-chunk."""

    read = staticmethod(ignition_provider.read_chunked_body)

    def test_reads_chunks(self):
        sock = FakeSocket(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        self.assertEqual(self.read(sock), b"hello world")

    def test_tolerates_extensions_and_trailers(self):
        sock = FakeSocket(b"5;name=v\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n")
        self.assertEqual(self.read(sock), b"hello")

    def test_large_chunk_across_many_reads(self):
        payload = b"x" * 10000
        sock = FakeSocket(b"%x\r\n" % len(payload), payload, b"\r\n0\r\n\r\n")
        self.assertEqual(self.read(sock), payload)

    def test_close_inside_a_chunk_is_an_error_not_a_hang(self):
        sock = FakeSocket(b"a\r\nhel")
        with self.assertRaises(ConnectionError):
            self.read(sock)

    def test_close_inside_a_size_line(self):
        with self.assertRaises(ConnectionError):
            self.read(FakeSocket(b"5"))

    def test_missing_crlf_after_chunk(self):
        with self.assertRaises(ValueError):
            self.read(FakeSocket(b"5\r\nhelloXX0\r\n\r\n"))


class TestMountTargetValidation(unittest.TestCase):
    """
    A virtiofs share mounted over a system directory hides everything the image
    put there, and the damage surfaces later as something that looks unrelated.
    etc-containers.mount was one instance and cost days; this is the general rule.
    """

    def unit(self, where):
        return "[Mount]\nWhat=tag\nWhere=%s\nType=virtiofs\n" % where

    def test_target_is_extracted_and_normalised(self):
        for written, expected in (
            ("/usr", "/usr"),
            ("/usr/", "/usr"),
            ("//usr", "/usr"),
            ("/usr/.", "/usr"),
            ("/var/folders/", "/var/folders"),
            ("/", "/"),
        ):
            self.assertEqual(
                ignition_provider.mount_unit_target(self.unit(written)), expected,
                "Where=%s should normalise to %s" % (written, expected))

    def test_target_ignores_comments_and_takes_the_last(self):
        contents = "[Mount]\n# Where=/decoy\nWhere=/first\nWhere=/second\n"
        self.assertEqual(ignition_provider.mount_unit_target(contents), "/second",
                         "systemd takes the last assignment, so this must too")

    def test_no_target(self):
        self.assertIsNone(ignition_provider.mount_unit_target(None))
        self.assertIsNone(ignition_provider.mount_unit_target("[Mount]\nWhat=tag\n"))

    def test_system_directories_are_refused(self):
        provider = IgnitionProvider()
        for target in ("/", "/usr", "/etc", "/home", "/var", "/dev", "/proc", "/sys"):
            with patch.object(ignition_provider, "Path") as mock_path:
                provider.enable_systemd_unit({
                    "name": "danger.mount",
                    "enabled": True,
                    "contents": self.unit(target),
                })
                mock_path.assert_not_called()

    def test_podmans_own_default_shares_are_allowed(self):
        # Rejecting everything under /var would reject a stock machine: podman
        # mounts /var/folders by default. It is mounting over /var that destroys.
        for target in ("/Users", "/private", "/var/folders", "/etc/containers",
                       "/home/core/work", "/opt/data"):
            self.assertNotIn(ignition_provider.mount_unit_target(self.unit(target)),
                             ignition_provider.FORBIDDEN_MOUNT_TARGETS,
                             "%s is a legitimate share target" % target)

    def test_forbidden_set_covers_the_documented_paths(self):
        for path in ("/bin", "/boot", "/dev", "/etc", "/home", "/proc", "/root",
                     "/run", "/sbin", "/sys", "/tmp", "/usr", "/var"):
            self.assertIn(path, ignition_provider.FORBIDDEN_MOUNT_TARGETS)

    def test_non_mount_units_are_untouched(self):
        # Only .mount units carry a Where=; a service naming one of these paths
        # must not be refused. Written into a real temporary directory: handing
        # the module a mock Path lets the genuine open() receive a MagicMock,
        # whose __index__ is 1, so it opens and then closes stdout.
        provider = IgnitionProvider()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)

        real_path = Path
        with patch.object(ignition_provider, "Path",
                          lambda p: real_path(tmp) / real_path(p).name), \
             patch("subprocess.run"):
            provider.enable_systemd_unit({
                "name": "harmless.service",
                "enabled": False,
                "contents": "[Service]\nExecStart=/bin/true\nWhere=/usr\n",
            })

        written = real_path(tmp) / "harmless.service"
        self.assertTrue(written.exists(),
                        "a .service must still be written even if it mentions /usr")
        self.assertIn("Where=/usr", written.read_text())


class TestPlaybookUnitAdaptation(unittest.TestCase):
    """
    podman writes playbook.service for Fedora CoreOS and gates it on
    ConditionFirstBoot=yes. That is never true in this image - on a real first
    boot systemd-firstboot, first-boot-complete.target and sshd-keygen were all
    skipped for exactly that reason - so applied unchanged the playbook would be
    skipped on every boot for ever, silently.
    """

    PODMAN_UNIT = (
        "[Unit]\n"
        "After=ready.service\n"
        "ConditionFirstBoot=yes\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "User=core\n"
        "Group=core\n"
        "ExecStart=ansible-playbook /home/core/playbook.yaml\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )

    def test_first_boot_condition_is_replaced(self):
        out = ignition_provider.adapt_playbook_unit(self.PODMAN_UNIT)
        self.assertNotIn("ConditionFirstBoot", out,
                         "the condition that never fires must be gone")
        self.assertIn("ConditionPathExists=!" + ignition_provider.PLAYBOOK_DONE_MARKER, out)

    def test_it_still_runs_only_once(self):
        out = ignition_provider.adapt_playbook_unit(self.PODMAN_UNIT)
        # '+' runs it as root; the unit itself runs as the machine user, who
        # cannot write to /var/lib, so without it the marker is never created
        # and the playbook runs on every boot.
        self.assertIn("ExecStartPost=+/bin/touch " + ignition_provider.PLAYBOOK_DONE_MARKER, out)

    def test_podmans_own_ordering_is_left_alone(self):
        # ready.service comes from the same Ignition config and is real here.
        out = ignition_provider.adapt_playbook_unit(self.PODMAN_UNIT)
        for keep in ("After=ready.service", "User=core", "Group=core",
                     "ExecStart=ansible-playbook /home/core/playbook.yaml",
                     "WantedBy=default.target"):
            self.assertIn(keep, out, "%s must survive the rewrite" % keep)

    def test_an_ungated_unit_gets_a_gate(self):
        ungated = "[Service]\nExecStart=ansible-playbook /home/core/playbook.yaml\n"
        out = ignition_provider.adapt_playbook_unit(ungated)
        self.assertIn("ConditionPathExists=!", out,
                      "nothing would otherwise stop it running on every boot")

    def test_nothing_to_adapt(self):
        self.assertIsNone(ignition_provider.adapt_playbook_unit(None))
        self.assertEqual(ignition_provider.adapt_playbook_unit(""), "")

    def test_only_playbook_service_is_adapted(self):
        # Any other unit carrying ConditionFirstBoot is podman's business.
        provider = IgnitionProvider()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        real_path = Path
        with patch.object(ignition_provider, "Path",
                          lambda p: real_path(tmp) / real_path(p).name), \
             patch("subprocess.run"):
            provider.enable_systemd_unit({
                "name": "other.service",
                "enabled": False,
                "contents": "[Unit]\nConditionFirstBoot=yes\n[Service]\nExecStart=/bin/true\n",
            })
        self.assertIn("ConditionFirstBoot=yes",
                      (real_path(tmp) / "other.service").read_text())


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
