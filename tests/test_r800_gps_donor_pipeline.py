"""Orchestration and real ext4 negative cases. Never executes donor code."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gps_donor_check as runner
from r800_gps_link_gate import DONORS


@unittest.skipUnless(shutil.which("debugfs") and shutil.which("mkfs.ext4"),
                     "e2fsprogs unavailable")
class DonorPipelineTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.image=self.root/"rootfs.img"
        self.out=self.root/"evidence"
        self.ndk=self.root/"ndk"
        self.ndk.mkdir()
        self.tree=self.root/"tree"
        (self.tree/"lib").mkdir(parents=True)
        self.sha="1"*40
        self.names=("libc","libdl","libpthread","ld")
        for name in self.names:
            (self.tree/"lib"/(name+"-2.24.so")).write_bytes(name.encode())

    def make_image(self):
        with self.image.open("wb") as stream:
            stream.truncate(16*1024**2)
        subprocess.run(["mkfs.ext4","-q","-F","-d",str(self.tree),str(self.image)],
                       check=True,timeout=30)
        self.digest=hashlib.sha256(self.image.read_bytes()).hexdigest()

    def invoke(self, qemu=False, expected=None):
        with mock.patch.object(runner.os,"getuid",return_value=1000), \
             mock.patch.object(runner,"git_state",return_value=(self.sha,True)):
            report=runner.run(self.image,expected or self.digest,self.ndk,self.out,qemu)
        self.assertEqual(json.loads((self.out/"report.json").read_text()),report)
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["gnss_runtime_verified"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(),self.digest)
        self.assertEqual(list(self.out.glob("r800-donor-*")),[])
        return report

    def test_real_ext4_rejects_non_elf_before_link(self):
        self.make_image()
        with mock.patch.object(runner,"execute_step") as launch:
            report=self.invoke(qemu=True)
        launch.assert_not_called()
        self.assertEqual(report["status"],"REVIEW_REQUIRED")
        self.assertEqual(report["gates"]["extraction"]["status"],"PASS")
        self.assertEqual(report["gates"]["elf"]["status"],"FAILED")
        self.assertEqual(report["gates"]["qemu"]["status"],"NOT_TESTED")

    def test_real_ext4_missing_loader(self):
        (self.tree/"lib/ld-2.24.so").unlink()
        self.make_image()
        with mock.patch.object(runner,"execute_step") as launch:
            report=self.invoke()
        launch.assert_not_called()
        self.assertEqual(report["gates"]["extraction"]["status"],"FAILED")
        self.assertEqual(report["status"],"REVIEW_REQUIRED")

    def test_real_ext4_wrong_hash(self):
        self.make_image()
        with mock.patch.object(runner,"execute_step") as launch:
            report=self.invoke(expected="0"*64)
        launch.assert_not_called()
        self.assertIn("SHA-256",report["reason"])
        self.assertEqual(report["gates"]["extraction"]["status"],"FAILED")

    def simulate(self, case, qemu=False):
        """Stub ELF/link/QEMU operations only; actual ext4 and evidence checks."""
        self.make_image()
        mapping=dict(zip(DONORS,self.names))
        hashes={k:hashlib.sha256(v.encode()).hexdigest() for k,v in mapping.items()}
        def elf(raw):
            return {"soname":next(k for k,v in mapping.items() if v.encode()==raw)}
        def audit(binary, libdir):
            return {"status":"STATIC_GLIBC_CLOSURE_ONLY","static_closure_pass":True,
                    "problems":[],"donor_sha256":hashes if case!="audit_mismatch" else {},
                    "safe_to_flash":False}
        def execute(command, cwd, path, seconds):
            if path.name=="link.log":
                Path(command[-1]).write_bytes(b"synthetic output")
                result=1 if case=="link_failure" else 0
                log="synthetic linker"
            else:
                result=0
                log="\n".join(["DONOR_SHA256 "+k+" "+v for k,v in hashes.items()]
                    + ["GLIBC_2_24=PASS","PTHREAD_TLS=PASS","DLOPEN_DLSYM=PASS",
                       "R800_GLIBC_QEMU_PROBE=PASS","QEMU_USER_ONLY=PASS",
                       "GNSS_RUNTIME_VERIFIED=false","safe_to_flash=false"])+"\n"
                if case=="wrong_runtime_hash":
                    log=log.replace(hashes[DONORS[0]],"0"*64)
                if case=="wrong_order":
                    log=log.replace("PTHREAD_TLS=PASS\nDLOPEN_DLSYM=PASS",
                                    "DLOPEN_DLSYM=PASS\nPTHREAD_TLS=PASS")
                if case=="duplicate_marker":
                    log+="QEMU_USER_ONLY=PASS\n"
            path.write_text(log)
            return {"exit_code":result,"log_sha256":hashlib.sha256(log.encode()).hexdigest(),
                    "log_file":path.name},log
        with mock.patch.object(runner,"elf",side_effect=elf), \
             mock.patch.object(runner,"audit",side_effect=audit), \
             mock.patch.object(runner,"execute_step",side_effect=execute) as launch:
            report=self.invoke(qemu)
        self.assertEqual(launch.call_count,2 if qemu and case not in
                         ("audit_mismatch","link_failure") else 1)
        for name in ("link","qemu"):
            gate=report["gates"][name]
            if "log_file" in gate:
                self.assertEqual(hashlib.sha256((self.out/gate["log_file"]).read_bytes()).hexdigest(),
                                 gate["log_sha256"])
        return report

    def test_static_only_simulated(self):
        r=self.simulate("ok")
        self.assertEqual(r["status"],"STATIC_DONOR_LINK_ONLY")
        self.assertEqual(r["gates"]["qemu"]["status"],"NOT_TESTED")

    def test_qemu_simulated(self):
        r=self.simulate("ok",True)
        self.assertEqual(r["status"],"DONOR_GLIBC_PROBE_ONLY")
        self.assertEqual(r["gates"]["qemu"]["status"],"PASS")

    def test_failed_link_blocks_qemu(self):
        r=self.simulate("link_failure",True)
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        self.assertEqual(r["gates"]["qemu"]["status"],"NOT_TESTED")

    def test_mismatched_static_hash_blocks_qemu(self):
        r=self.simulate("audit_mismatch",True)
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        self.assertEqual(r["gates"]["qemu"]["status"],"NOT_TESTED")

    def test_wrong_runtime_hash(self):
        r=self.simulate("wrong_runtime_hash",True)
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        self.assertEqual(r["gates"]["qemu"]["status"],"FAILED")

    def test_wrong_runtime_order(self):
        r=self.simulate("wrong_order",True)
        self.assertEqual(r["gates"]["qemu"]["status"],"FAILED")

    def test_duplicate_runtime_marker(self):
        r=self.simulate("duplicate_marker",True)
        self.assertEqual(r["gates"]["qemu"]["status"],"FAILED")


if __name__=="__main__":
    unittest.main()
