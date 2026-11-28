"""Entry observation classification and pinned loader evidence contracts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_runtime_entry_qemu as probe


class RuntimeEntryTests(unittest.TestCase):
    log=b"dlopen: /usr/lib/libbrcm.so: cannot open shared object file: No such file or directory\n"

    def test_reference_expected_failure(self):
        self.assertEqual(probe.classify(probe.REFERENCE,probe.BRIDGE,1,self.log),
                         "REFERENCE_EXPECTED_MISSING_LIBBRCM")

    def test_reference_wrong_failure(self):
        for rc,raw in ((0,self.log),(1,b"other failure"),(124,self.log),(1,self.log+b"extra\n")):
            with self.subTest(rc=rc,raw=raw),self.assertRaisesRegex(ValueError,"expected missing"):
                probe.classify(probe.REFERENCE,probe.BRIDGE,rc,raw)

    def test_local_exit_is_not_acceptance(self):
        for rc,status in ((0,"EXIT_ZERO_REVIEW"),(1,"NONZERO_EXIT_REVIEW"),(124,"BOUNDED_TIMEOUT_REVIEW")):
            self.assertEqual(probe.classify(probe.LOCAL,"/usr/bin/lhd",rc,b""),status)

    def test_transcript_bound(self):
        with self.assertRaisesRegex(ValueError,"exceeds budget"):
            probe.classify(probe.LOCAL,"/usr/bin/lhd",1,b"x"*(probe.MAX_LOG+1))

    def test_loader_evidence_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"loader.json"
            report={"schema":"galwear-r800-loader-qemu-v1","status":"ARM32_LOADER_LIST_PASS",
                    "source_sha":"a"*40,"scope":probe.REFERENCE,
                    "runtime_evidence_sha256":"b"*64,"safe_to_flash":False,
                    "checks":{probe.BRIDGE:{"exit_code":0}}}
            raw=json.dumps(report).encode()
            path.write_bytes(raw)
            self.assertEqual(probe.loader_report(path,probe.sha(raw),"b"*64,probe.REFERENCE,
                                                 "a"*40,[probe.BRIDGE]),(raw,report))
            with self.assertRaisesRegex(ValueError,"Same-runtime"):
                probe.loader_report(path,probe.sha(raw),"c"*64,probe.REFERENCE,"a"*40,[probe.BRIDGE])
            with self.assertRaisesRegex(ValueError,"pin mismatch"):
                probe.loader_report(path,"0"*64,"b"*64,probe.REFERENCE,"a"*40,[probe.BRIDGE])


if __name__=="__main__":
    unittest.main()
