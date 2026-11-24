"""Synthetic exact-head integration evidence gate tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_integration_evidence import validate, digest, BASE, MODULES

ROOT = Path(__file__).resolve().parents[1]


class IntegrationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.identity = {"commit": "a" * 40, "run_id": "123", "run_attempt": "1", "safe_to_flash": False}
        self.emit("r800-integrated-regression.json", "galwear-r800-integrated-regression-v1", "PASS",
                  executed=10, discovered=10, failures=[], errors=[], skipped=[],
                  expected_failures=[], unexpected_successes=[])
        self.emit("hal-compile.json", "galwear-r800-hal-compile-v1", "FOUR_ARM32_OBJECTS_COMPILED",
                  abi="armeabi-v7a", api_level=28, ndk="27.2.12479018",
                  objects={stem: {"source_sha256": digest(ROOT / "src/hal" / (stem + ".c")),
                                  "object_sha256": "b" * 64} for stem in MODULES})
        self.emit("hal-link.json", "galwear-r800-hal-link-v1", "FOUR_ARM32_HAL_LIBRARIES_LINKED",
                  modules={name: {"sha256": "c" * 64, "hmi_exported": True, "soname": name}
                           for name in MODULES.values()},
                  compile_evidence_sha256=digest(self.directory / "hal-compile.json"),
                  tinyalsa_patch_sha256=digest(ROOT / "build/patches/tinyalsa-2.0.0-sync-ptr.patch"))
        self.emit("decon-abi.json", "galwear-r800-decon-abi-v1", "LAYOUT_COMPILED_BOTH_ABIS",
                  source_commit=BASE, targets=["armv7a", "aarch64"],
                  mirror_sha256=digest(ROOT / "src/hal/r800_decon_abi.h"))
        self.emit("r800-patch-check.json", "galwear-r800-kernel-preflight-v1",
                  "PATCH_APPLIES_TO_PINNED_SOURCE_ONLY",
                  patch_matches_supplied_kernel_tree=True,
                  source_audit={"pinned_source_base_sha": BASE, "git_apply_check": "PASS"},
                  static_patch_audit={"patch_sha256": digest(ROOT / "src/kernel/r800-wearos.patch")},
                  kernel_config_audit={"config_sha256": digest(ROOT / "src/kernel/r800.config")},
                  device_tree_sha256=digest(ROOT / "src/dt/r800.dts"))

    def emit(self, name, schema, status, **kwargs):
        (self.directory / name).write_text(json.dumps(dict(self.identity, schema=schema, status=status, **kwargs)))

    def mutate(self, name, **kwargs):
        p = self.directory / name
        obj = json.loads(p.read_text())
        obj.update(kwargs)
        p.write_text(json.dumps(obj))

    def check(self):
        return validate(ROOT, self.directory, "a" * 40, "123", "1")

    def test_match(self):
        result = self.check()
        self.assertEqual(result["status"], "HOST_REGRESSION_AND_HAL_LINK_EVIDENCE_MATCH")
        self.assertFalse(result["kernel_compiled"])
        self.assertFalse(result["safe_to_flash"])

    def test_missing_link(self):
        (self.directory / "hal-link.json").unlink()
        with self.assertRaises(ValueError):
            self.check()

    def test_stale_commit(self):
        self.mutate("hal-link.json", commit="d" * 40)
        with self.assertRaises(ValueError):
            self.check()

    def test_stale_attempt(self):
        self.mutate("decon-abi.json", run_attempt="2")
        with self.assertRaises(ValueError):
            self.check()

    def test_skipped(self):
        self.mutate("r800-integrated-regression.json", skipped=["test_fixture"])
        with self.assertRaises(ValueError):
            self.check()

    def test_compilation_digest_mismatch(self):
        self.mutate("hal-compile.json", extra="changed after link")
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_patch(self):
        self.mutate("r800-patch-check.json", static_patch_audit={"patch_sha256": "0" * 64})
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
