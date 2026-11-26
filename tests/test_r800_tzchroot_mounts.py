"""Execute actual chroot mount helpers with synthetic mount records and directories."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"src/tools/sensors/tzchroot.sh").read_text()
HELPERS=SOURCE.split("# BEGIN TZCHROOT_MOUNT_HELPERS\n",1)[1].split("# END TZCHROOT_MOUNT_HELPERS",1)[0]


class MountHelperTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.mounts=self.root/"mounts"
        self.mounts.write_text("")
        self.a=self.root/"a"
        self.b=self.root/"b"
        self.a.mkdir()
        self.b.mkdir()
        self.link=self.root/"alias"
        self.link.symlink_to(self.a,target_is_directory=True)

    def run_helper(self,body,expected=0):
        # Never invoke the host mount command, even on a missing record.
        script=r'''
B=fixture
MOUNTS=$1
A=$2
C=$3
L=$4
fixture() {
    if [ "$1" = mount ]; then
        printf 'mock mount failure\n' >&2
        return 1
    fi
    "$@"
}
'''+HELPERS+"\n"+body+"\necho fixture-ready\n"
        p=subprocess.run(["sh","-c",script,"fixture",str(self.mounts),
                          str(self.a),str(self.b),str(self.link)],
                         capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,expected,p.stdout+p.stderr)
        self.assertEqual("fixture-ready" in p.stdout,expected==0)
        return p

    def record(self,target,kind="tmpfs",options="rw,nosuid"):
        return f"fixture {target} {kind} {options} 0 0\n"

    def test_exact_mount_target(self):
        self.mounts.write_text(self.record(str(self.a)+"-other"))
        self.run_helper('if mounted "$A"; then exit 1; fi')

    def test_ambiguous_record(self):
        self.mounts.write_text(self.record(self.a)*2)
        self.run_helper('require mount_record "$A"',1)

    def test_readonly(self):
        self.mounts.write_text(self.record(self.a,"ext4","ro,noatime"))
        self.run_helper('require mount_access "$A" ro')

    def test_writable_root_rejected(self):
        self.mounts.write_text(self.record(self.a,"ext4","rw,noatime"))
        self.run_helper('require mount_access "$A" ro',1)

    def test_tmpfs_existing(self):
        self.mounts.write_text(self.record(self.a))
        self.run_helper('tmpfs_mount "$A" size=8m,mode=755')

    def test_wrong_filesystem(self):
        self.mounts.write_text(self.record(self.a,"ext4"))
        self.run_helper('tmpfs_mount "$A" size=8m,mode=755',1)

    def test_mount_failure_stops(self):
        self.run_helper('tmpfs_mount "$A" size=8m,mode=755',1)

    def test_bind_existing_same_object(self):
        self.mounts.write_text(self.record(self.link,"ext4"))
        self.run_helper('bind_mount "$A" "$L"')

    def test_bind_existing_wrong_object(self):
        self.mounts.write_text(self.record(self.b,"ext4"))
        self.run_helper('bind_mount "$A" "$C"',1)

    def test_bind_mount_failure(self):
        self.run_helper('bind_mount "$A" "$C"',1)

    def test_charger_status_not_pipe(self):
        start=(ROOT/"payload/start.sh").read_text()
        self.assertIn('if tz_result=$("$B" timeout 60 "$B" sh /data/r800dev/tzchroot.sh 2>&1); then',start)
        self.assertIn("sensor chroot blocked; continue charging without lhd",start)


if __name__=="__main__":
    unittest.main()
