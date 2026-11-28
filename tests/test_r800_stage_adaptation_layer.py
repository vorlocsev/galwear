"""Composition contracts only; fixture bytes are not actual Tizen binaries."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_stage_adaptation_layer as layer


class AdaptationLayerTests(unittest.TestCase):
    source = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.device, self.runtime = self.root/"device", self.root/"runtime"
        self.device.mkdir()
        self.runtime.mkdir()
        self.out = self.root/"out"
        self.dp = self.fixture(self.device, False)
        self.rp = self.fixture(self.runtime, True)

    def fixture(self, root, runtime):
        if runtime:
            modes = {n: ("0o755" if n == "r800dev/gpsbridge" or
                         n.startswith("r800dev/tzlite/usr/bin/") or
                         n.endswith("/ld-linux.so.3") else "0o644")
                     for n in layer.RUNTIME_REQUIRED}
            report = dict(schema="galwear-r800-tizen-runtime-v1",
                          status="LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY",
                          tizen_image_sha256="b"*64, closure_manifest_sha256="c"*64)
            flags = ("same_origin_proven","donor_authenticity_verified","configuration_complete",
                     "plugins_complete","full_runtime_built","gnss_runtime_verified")
            name = "tizen-runtime-evidence.json"
        else:
            modes = layer.DEVICE
            report = dict(schema="galwear-r800-device-layer-v1",
                          status="COMPILED_DEVICE_LAYER_STAGED_ONLY",
                          component_manifest_sha256="d"*64)
            flags = ("donor_images_used","complete_vendor_built","android_handover_tested","payload_complete")
            name = "device-layer-evidence.json"
        report.update({f:False for f in (*flags,"hardware_tested","safe_to_flash")})
        report["source_sha"] = self.source
        files = {}
        for path, mode in sorted(modes.items()):
            # Both copies of a HAL or wpcd must have identical fixture bytes.
            data = Path(path).name.encode()
            p = root/path
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(data)
            p.chmod(int(mode,8))
            files[path] = dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=mode)
        report["files"] = files
        report["total_bytes"] = sum(row["bytes"] for row in files.values())
        if runtime:
            report["gpsbridge_sha256"] = files["r800dev/gpsbridge"]["sha256"]
            report["library_sha256"] = {n:files["r800dev/tzlite/lib/"+n]["sha256"] for n in layer.DONORS}
        raw=json.dumps(report).encode()
        (root/name).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def mutate(self, runtime, change):
        root = self.runtime if runtime else self.device
        path = root/("tizen-runtime-evidence.json" if runtime else "device-layer-evidence.json")
        obj=json.loads(path.read_text())
        change(obj)
        raw=json.dumps(obj).encode()
        path.write_bytes(raw)
        if runtime:
            self.rp=hashlib.sha256(raw).hexdigest()
        else:
            self.dp=hashlib.sha256(raw).hexdigest()

    def run_stage(self, bad_audit=False):
        r=json.loads((self.runtime/"tizen-runtime-evidence.json").read_text())
        result=dict(status="STATIC_GLIBC_CLOSURE_ONLY",sha256=r["gpsbridge_sha256"],
                    donor_sha256=r["library_sha256"])
        if bad_audit:
            result["sha256"]="0"*64
        with patch.object(layer,"checkout_sha"), patch.object(layer,"audit",return_value=result):
            return layer.assemble(self.device,self.dp,self.runtime,self.rp,self.out,self.source)

    def test_composition(self):
        result=self.run_stage()
        self.assertEqual(result["status"],"DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY")
        self.assertEqual(set(result["files"]),set(layer.DEVICE)|layer.RUNTIME_REQUIRED)
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse(result["payload_complete"])
        self.assertTrue((self.out/"r800dev/gpsbridge").is_file())
        self.assertFalse((self.out/"r800dev/android").exists())

    def test_wrong_pin(self):
        self.rp="0"*64
        with self.assertRaisesRegex(ValueError,"pin mismatch"):
            self.run_stage()
        self.assertFalse(self.out.exists())

    def test_stale_source(self):
        self.mutate(True,lambda r:r.update(source_sha="b"*40))
        with self.assertRaisesRegex(ValueError,"scope or source SHA"):
            self.run_stage()

    def test_reference_scope_rejected(self):
        self.mutate(True,lambda r:r.update(status="GPS_RUNTIME_SUBSET_STAGED_ONLY"))
        with self.assertRaisesRegex(ValueError,"scope or source SHA"):
            self.run_stage()

    def test_claimed_flash_permission_rejected(self):
        self.mutate(True,lambda r:r.update(safe_to_flash=True))
        with self.assertRaisesRegex(ValueError,"scope or source SHA"):
            self.run_stage()

    def test_unlisted_file_rejected(self):
        (self.runtime/"extra").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError,"Unexpected layer entry"):
            self.run_stage()

    def test_changed_file(self):
        (self.device/"r800dev/start.sh").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"Layer bytes changed"):
            self.run_stage()

    def test_symlink_rejected(self):
        p=self.runtime/"r800dev/gpsbridge"
        p.unlink()
        p.symlink_to(self.device/"r800dev/start.sh")
        with self.assertRaisesRegex(ValueError,"Unexpected layer entry"):
            self.run_stage()

    def test_final_link_mismatch(self):
        with self.assertRaisesRegex(ValueError,"Final GPSBridge audit mismatch"):
            self.run_stage(bad_audit=True)
        self.assertFalse(self.out.exists())

    def test_output_exists(self):
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError,"Fresh output"):
            self.run_stage()


if __name__=="__main__":
    unittest.main()
