"""Offline source guards for ABOX async request and copy bounds."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


class AboxFirmwareTests(unittest.TestCase):
    def test_single_request_and_submission_failure(self):
        p = PATCH.read_text()
        self.assertIn("atomic_cmpxchg(&abox_fw_inflight, 0, 1)", p)
        self.assertIn("+\tret = request_firmware_nowait(", p)
        self.assertIn("SRAM request submission failed", p)
        self.assertIn("atomic_inc_return(&abox_fw_retries)", p)
        self.assertIn("attempt <= ABOX_FW_RETRY_MAX", p)

    def test_validate_images_before_copy(self):
        p = PATCH.read_text()
        start = p.index("/* Validate both images before any copy")
        end = p.index("memcpy_toio(data->sram_base", start)
        part = p[start:end]
        self.assertIn("data->firmware_sram->size > data->sram_size", part)
        self.assertIn("data->firmware_dram->size > DRAM_FIRMWARE_SIZE", part)
        self.assertIn("SZ_512 > data->sram_size - data->bootargs_offset", part)
        self.assertIn("return -EINVAL", part)

    def test_dram_before_sram_publication_and_stop(self):
        p = PATCH.read_text()
        start = p.index("/* Publish SRAM only after DRAM")
        end = p.index("smp_store_release(&data->firmware_sram, fw)", start)
        self.assertIn("abox_request_firmware(dev, &data->firmware_dram", p[start:end])
        self.assertIn("goto retry", p[start:end])
        self.assertIn("cancel_delayed_work_sync(&abox_fw_retry_work)", p)
        self.assertIn("wait_for_completion(&abox_fw_idle)", p)

    def test_poweroff_remains_explicit_opt_in(self):
        p = PATCH.read_text()
        self.assertIn("+static int r800_rtpm_poweroff;", p)
        self.assertIn("if (r800_rtpm_poweroff &&", p)


if __name__ == "__main__":
    unittest.main()
