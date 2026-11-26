"""Execute the actual helper's read-only IPC metadata functions on host fixtures."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class StartupMetadataTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.dir=self.root/"ipc"
        self.dir.mkdir(mode=0o755)
        self.dir.chmod(0o755)
        self.uid=str(os.getuid())
        self.busybox=self.root/"busybox"
        self.busybox.write_text('#!/bin/sh\nexec "$@"\n')
        self.busybox.chmod(0o700)
        source=(ROOT/"payload/android-helper.sh").read_text()
        self.functions=source.split("# BEGIN GNSS_IPC_METADATA\n",1)[1].split("# END GNSS_IPC_METADATA",1)[0]

    def call(self,func,other=None,uid=None):
        script=self.functions+'\nB=$1\n'+func+' "$2" "$3" "$4"\n'
        proc=subprocess.run(["sh","-c",script,"test",str(self.busybox),
                             str(self.dir),str(other or self.dir),uid or self.uid],
                            capture_output=True,timeout=5)
        return proc.returncode==0

    def create_socket(self):
        peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(peer.close)
        peer.bind(str(self.dir/"gps.sock"))
        (self.dir/"gps.sock").chmod(0o660)
        # No listen() or actual IPC exchange: metadata alone is not readiness.
        marker=self.dir/"gps.sock.owner"
        marker.write_bytes(bytes(40))
        marker.chmod(0o600)
        return marker

    def test_same_directory(self):
        self.assertTrue(self.call("gnss_ipc_directory"))

    def test_distinct_directory(self):
        other=self.root/"other"
        other.mkdir()
        self.assertFalse(self.call("gnss_ipc_directory",other))

    def test_directory_symlink(self):
        link=self.root/"link"
        link.symlink_to(self.dir,target_is_directory=True)
        self.assertFalse(self.call("gnss_ipc_directory",link))

    def test_untrusted_permissions(self):
        for mode in (0o775,0o757,0o1777):
            self.dir.chmod(mode)
            self.assertFalse(self.call("gnss_ipc_directory"))

    def test_wrong_owner(self):
        self.assertFalse(self.call("gnss_ipc_directory",uid=str(os.getuid()+1)))

    def test_missing_socket(self):
        self.assertFalse(self.call("gnss_socket_metadata"))

    def test_socket_metadata_only(self):
        marker=self.create_socket()
        self.assertTrue(self.call("gnss_socket_metadata"))
        self.assertEqual(marker.read_bytes(),bytes(40))

    def test_socket_mode(self):
        self.create_socket()
        (self.dir/"gps.sock").chmod(0o666)
        self.assertFalse(self.call("gnss_socket_metadata"))

    def test_marker_size(self):
        marker=self.create_socket()
        marker.write_bytes(b"bad")
        self.assertFalse(self.call("gnss_socket_metadata"))

    def test_marker_symlink(self):
        marker=self.create_socket()
        target=self.root/"target"
        marker.rename(target)
        marker.symlink_to(target)
        self.assertFalse(self.call("gnss_socket_metadata"))

    def test_marker_hardlink(self):
        marker=self.create_socket()
        os.link(marker,self.root/"duplicate")
        self.assertFalse(self.call("gnss_socket_metadata"))


if __name__=="__main__":
    unittest.main()
