"""Synthetic evidence gates; no donor execution."""
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_pixel_hal_fixture_summary as summary


class PixelFixtureSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source="a"*40
        self.pins={k:format(i+1,"064x") for i,k in enumerate(sorted(summary.RUNTIME))}
        self.hals={k:format(i+11,"064x") for i,k in enumerate(sorted(summary.HALS))}
        self.write("pixel-bionic-extraction",{
            "source_sha":self.source,"status":"ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY",
            "raw_system_sha256":summary.SYSTEM_PIN,"system_sha256":summary.SYSTEM_PIN,
            "apex_layout":"FLATTENED_APEX","linker_provides_ld_android":True,
            "safe_to_flash":False,"files":{k:{"sha256":v} for k,v in self.pins.items()}})
        self.write("pixel-hal-compile",{
            "commit":self.source,"abi":"armeabi-v7a","safe_to_flash":False,
            "audio_candidate":{"sha256":self.hals["audio.primary.r800.so"]},
            "linked_libraries":{k.split(".")[0]:{"sha256":v} for k,v in self.hals.items()
                                if not k.startswith("audio.")}})
        baseline=self.probe("ARM32_HAL_HMI_QEMU_USER_ONLY","HMI_ONLY_PASS",summary.HALS)
        baseline["hal_open_called"]=False
        self.write("pixel-hal-runtime",baseline)
        for mode,(status,marker,modules) in summary.MODES.items():
            self.write("pixel-hal-"+mode,self.probe(status,marker,modules))

    def write(self,name,data):
        (self.root/(name+".json")).write_text(json.dumps(data))

    def probe(self,status,marker,modules):
        return {"source_sha":self.source,"runtime_sha256":dict(self.pins),
                "hal_sha256":dict(self.hals),"hardware_tested":False,"safe_to_flash":False,
                "status":status,"results":{k:{"status":marker,"exit_code":0} for k in modules}}

    def change(self,name,fn):
        p=self.root/(name+".json")
        d=json.loads(p.read_text())
        fn(d)
        self.write(name,d)

    def test_complete(self):
        r=summary.summarize(self.root,self.source)
        self.assertEqual(r["status"],"PIXEL_HAL_SYNTHETIC_FIXTURES_ONLY")
        self.assertEqual(len(r["modes"]),10)
        self.assertTrue(all(v["status"]=="PASS" for v in r["modes"].values()))
        self.assertFalse(r["safe_to_flash"])

    def test_missing(self):
        (self.root/"pixel-hal-gps-fixture.json").unlink()
        r=summary.summarize(self.root,self.source)
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        self.assertEqual(r["modes"]["gps-fixture"]["status"],"NOT_TESTED")

    def test_wrong_head_or_runtime_or_hals(self):
        for key,value in (("source_sha","b"*40),("runtime_sha256",{}),("hal_sha256",{})):
            with self.subTest(key=key):
                self.change("pixel-hal-lifecycle",lambda d:d.update({key:value}))
                self.assertEqual(summary.summarize(self.root,self.source)["modes"]["lifecycle"]["status"],"REVIEW_REQUIRED")
                self.write("pixel-hal-lifecycle",self.probe(*summary.MODES["lifecycle"]))

    def test_empty_results_and_boolean_exit(self):
        self.change("pixel-hal-gps-fixture",lambda d:d.update(results={}))
        self.assertEqual(summary.summarize(self.root,self.source)["modes"]["gps-fixture"]["status"],"REVIEW_REQUIRED")
        self.write("pixel-hal-gps-fixture",self.probe(*summary.MODES["gps-fixture"]))
        self.change("pixel-hal-gps-fixture",lambda d:d["results"]["gps.r800.so"].update(exit_code=False))
        self.assertEqual(summary.summarize(self.root,self.source)["modes"]["gps-fixture"]["status"],"REVIEW_REQUIRED")

    def test_wrong_compile_hash(self):
        self.change("pixel-hal-compile",lambda d:d["audio_candidate"].update(sha256="f"*64))
        with self.assertRaisesRegex(ValueError,"HMI baseline mismatch"):
            summary.summarize(self.root,self.source)

    def test_wrong_system(self):
        self.change("pixel-bionic-extraction",lambda d:d.update(raw_system_sha256="b"*64))
        with self.assertRaisesRegex(ValueError,"runtime evidence mismatch"):
            summary.summarize(self.root,self.source)

    def test_duplicate_key(self):
        (self.root/"pixel-hal-gps-fixture.json").write_text('{"status":"PASS","status":"PASS"}')
        self.assertEqual(summary.summarize(self.root,self.source)["modes"]["gps-fixture"]["status"],"REVIEW_REQUIRED")


if __name__=="__main__":
    unittest.main()
