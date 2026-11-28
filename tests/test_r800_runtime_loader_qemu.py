"""Loader transcript and inventory contracts; real QEMU runs in reference CI."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_runtime_loader_qemu as probe


class LoaderProbeTests(unittest.TestCase):
    inventory={"/lib/libc.so.6":"a"*64,"/lib/ld-linux.so.3":"b"*64}
    log=b"libc.so.6 => /lib/libc.so.6 (0x1234)\n/lib/ld-linux.so.3 (0x5678)\n"

    def test_exact_resolution(self):
        found=probe.transcript(self.log,0,self.inventory,["libc.so.6"])
        self.assertEqual(found["libc.so.6"]["sha256"],"a"*64)
        self.assertEqual(found["ld-linux.so.3"]["path"],probe.LOADER)

    def test_unresolved(self):
        with self.assertRaisesRegex(ValueError,"Unexpected or unresolved"):
            probe.transcript(b"libc.so.6 => not found\n",0,self.inventory,["libc.so.6"])

    def test_wrong_path(self):
        with self.assertRaisesRegex(ValueError,"Unexpected or duplicate"):
            probe.transcript(self.log.replace(b"/lib/libc",b"/usr/lib/libc"),0,self.inventory,["libc.so.6"])

    def test_duplicate_provider(self):
        with self.assertRaisesRegex(ValueError,"duplicate"):
            probe.transcript(self.log+self.log,0,self.inventory,["libc.so.6"])

    def test_missing_direct_needed(self):
        with self.assertRaisesRegex(ValueError,"Missing direct"):
            probe.transcript(self.log,0,self.inventory,["libpthread.so.0"])

    def test_failed_probe(self):
        with self.assertRaisesRegex(ValueError,"failed or timed out"):
            probe.transcript(self.log,124,self.inventory,["libc.so.6"])

    def test_reference_scope_and_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            files={"reference-runtime/gpsbridge":{}}
            files.update({"reference-runtime/lib/"+n:{} for n in probe.DONORS})
            report={"schema":"galwear-r800-runtime-layer-v1","status":"GPS_RUNTIME_SUBSET_STAGED_ONLY",
                    "source_sha":"a"*40,"safe_to_flash":False,"scope":probe.REFERENCE,"files":files}
            raw=json.dumps(report).encode()
            (root/"runtime-layer-evidence.json").write_bytes(raw)
            _,_,rows,targets=probe.source_rows(root,probe.sha(raw),probe.REFERENCE,"a"*40)
            self.assertEqual(targets,[probe.BRIDGE])
            self.assertEqual(set(rows),{probe.BRIDGE,*("/lib/"+n for n in probe.DONORS)})
            with self.assertRaisesRegex(ValueError,"pin mismatch"):
                probe.source_rows(root,"0"*64,probe.REFERENCE,"a"*40)


if __name__=="__main__":
    unittest.main()
