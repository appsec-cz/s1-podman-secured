"""Exercise failed transfers and restores, including the host's deletion gate."""
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = (ROOT / "deploy.sh").read_text()
TRANSFER = ROOT / "scripts/podman-volume-transfer.sh"


def guest_script(name):
    return DEPLOY.split(name + "='\n", 1)[1].split("\n'\n", 1)[0]


class MigrationSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="s1 migration ")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.backup = self.base / "backup"
        self.backup.mkdir()
        for name in ("images.txt", "volumes.txt", "expected.txt", "pods.txt", "running.txt"):
            (self.backup / name).touch()
        (self.backup / "manifest.json").write_text("{}")
        (self.backup / "containers").mkdir()
        (self.backup / "volumes").mkdir()
        self.archive = self.base / "volume.tar"
        with tarfile.open(self.archive, "w") as archive:
            content = b"volume payload\x00\xff\n"
            entry = tarfile.TarInfo("marker")
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.log = self.base / "calls"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CALLS=str(self.log), FIXTURE=str(self.archive), DIR=str(self.backup))

    def stub(self, body):
        path = self.bin / "podman"
        path.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n' + body)
        path.chmod(0o755)

    def run_guest(self, name):
        return subprocess.run(["bash", "-c", guest_script(name)], env=self.env,
                              capture_output=True, text=True)

    def volume_fixture(self):
        (self.backup / "volumes.txt").write_text("data\n")
        (self.backup / "volumes/data.tar").write_bytes(self.archive.read_bytes())
        (self.backup / "expected.txt").write_text("web\n")
        (self.backup / "running.txt").write_text("web\n")
        (self.backup / "containers/web.yaml").touch()

    def test_missing_volume_archive_stops_before_any_podman_call(self):
        self.volume_fixture()
        (self.backup / "volumes/data.tar").unlink()
        self.stub("exit 0\n")
        result = self.run_guest("RESTORE_GUEST_SCRIPT")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RESTORE_FAIL", result.stdout)
        self.assertFalse(self.log.exists())

    def test_failed_import_never_plays_or_starts_containers(self):
        self.volume_fixture()
        self.stub('[ "$1 $2" = "volume import" ] && exit 125\nexit 0\n')
        result = self.run_guest("RESTORE_GUEST_SCRIPT")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RESTORE_FAIL volume data", result.stdout)
        self.assertNotIn("RESTORE_OK", result.stdout)
        self.assertNotIn("kube play", self.log.read_text())
        self.assertNotIn("start web", self.log.read_text())

    def test_first_create_failure_cannot_be_hidden_by_second_success(self):
        self.volume_fixture()
        # Generate the actual creation script, with two volumes.
        (self.backup / "volumes.json").write_text('[{"Name":"bad"},{"Name":"good"}]')
        result = self.run_host('write_volume_create_script "$DIR"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.stub('[ "$1 $2 $3" = "volume create bad" ] && exit 125\nexit 0\n')
        result = self.run_guest("RESTORE_GUEST_SCRIPT")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RESTORE_FAIL volume create", result.stdout)
        self.assertNotIn("volume import", self.log.read_text())

    def test_successful_guest_restore_has_explicit_completion(self):
        self.volume_fixture()
        self.stub('case "$1 $2" in "container exists") exit 1;; esac\nexit 0\n')
        result = self.run_guest("RESTORE_GUEST_SCRIPT")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RESTORE_OK", result.stdout)
        self.assertIn("start web", self.log.read_text())

    def test_failed_inventory_does_not_verify_an_empty_backup(self):
        self.stub("exit 125\n")
        result = self.run_guest("VERIFY_GUEST_SCRIPT")
        self.assertIn("VERIFY_FAILED", result.stdout)
        self.assertNotIn("VERIFY_OK", result.stdout)

    def run_host(self, commands):
        # Source functions without running main; no real machine is involved.
        script = DEPLOY.rsplit('\nmain "$@"', 1)[0] + "\n" + commands
        return subprocess.run(["bash", "-c", script], env=self.env,
                              capture_output=True, text=True)

    def test_host_keeps_backup_on_import_failure_or_ssh_disconnect(self):
        for output, rc in (("RESTORE_FAIL volume data", 0), ("", 255),
                           ("", 0), ("RESTORE_OK", 255)):
            with self.subTest(output=output, rc=rc):
                commands = '''
require_machine_running() { :; }
podman() { echo false; }
write_volume_create_script() { :; }
guest_script() { printf '%s\\n' "$MOCK_OUTPUT"; return "$MOCK_RC"; }
discard_backup() { touch "$DIR/deleted"; }
restore_machine "$DIR"
'''
                self.env.update(MOCK_OUTPUT=output, MOCK_RC=str(rc))
                result = self.run_host(commands)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.backup / "deleted").exists())
                self.assertIn("Backup kept", result.stdout)

    def test_host_requires_successful_verification_transport(self):
        result = self.run_host('''
require_machine_running() { :; }
podman() { echo false; }
write_volume_create_script() { :; }
guest_script() {
    if [ "$1" = "$RESTORE_GUEST_SCRIPT" ]; then echo RESTORE_OK;
    else echo VERIFY_OK; return 255; fi
}
discard_backup() { touch "$DIR/deleted"; }
restore_machine "$DIR"
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.backup / "deleted").exists())

    def test_host_discards_only_after_both_stages_complete(self):
        result = self.run_host('''
require_machine_running() { :; }
podman() { echo false; }
write_volume_create_script() { :; }
guest_script() {
    if [ "$1" = "$RESTORE_GUEST_SCRIPT" ]; then echo RESTORE_OK;
    else echo VERIFY_OK; fi
}
discard_backup() { touch "$DIR/deleted"; }
restore_machine "$DIR"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.backup / "deleted").exists())

    def run_transfer(self, *args):
        return subprocess.run(["bash", str(TRANSFER), *args], env=self.env,
                              capture_output=True, text=True)

    def transfer_stub(self):
        self.stub('''
if [ "$1 $2" = "machine inspect" ]; then echo "${ROOTFUL:-false}"; exit 0; fi
case "$4" in
    *"volume exists"*) exit 0 ;;
    *"volume export"*) cat "$FIXTURE"; exit "${TRANSFER_RC:-0}" ;;
    *"volume import"*) cat > "$CALLS.input"; exit "${TRANSFER_RC:-0}" ;;
esac
exit 99
''')

    def test_transfer_import_streams_binary_archive_into_guest(self):
        self.transfer_stub()
        result = self.run_transfer("import", "data", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(str(self.log) + ".input").read_bytes(), self.archive.read_bytes())
        self.assertIn("machine ssh podman-machine-default podman volume import data -", self.log.read_text())

    def test_failed_export_preserves_previous_archive_and_cleans_temporary_file(self):
        self.transfer_stub()
        target = self.base / "old backup.tar"
        target.write_bytes(b"previous good backup")
        self.env["TRANSFER_RC"] = "125"
        result = self.run_transfer("export", "data", str(target))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"previous good backup")
        self.assertEqual(list(self.base.glob("*.part.*")), [])

    def test_transfer_uses_rootful_store_and_explicit_machine(self):
        self.transfer_stub()
        self.env["ROOTFUL"] = "true"
        result = self.run_transfer("--machine", "custom", "import", "data", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("machine ssh custom sudo -n podman volume import data -", self.log.read_text())

    def test_failed_import_returns_failure(self):
        self.transfer_stub()
        self.env["TRANSFER_RC"] = "125"
        self.assertNotEqual(self.run_transfer("import", "data", str(self.archive)).returncode, 0)

    def test_invalid_archive_does_not_reach_import(self):
        self.transfer_stub()
        self.archive.write_bytes(b"not an archive")
        self.assertNotEqual(self.run_transfer("import", "data", str(self.archive)).returncode, 0)
        self.assertNotIn("volume import", self.log.read_text())

    def test_volume_name_cannot_inject_a_remote_command(self):
        self.transfer_stub()
        result = self.run_transfer("import", "data; touch injected", str(self.archive))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
