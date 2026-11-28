"""Read-only runtime directory inventory tests."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_pixel_runtime_layout as layout


class RuntimeLayoutTests(unittest.TestCase):
    def test_listing(self):
        rows=layout.parse_listing("/2/040755/0/0/.//\n/2/040755/0/0/..//\n"
                                  "/12/040755/0/0/com.android.runtime//\n"
                                  "/13/100644/0/0/file.apex/123/\n"
                                  "/14/120777/0/0/link/4/\n")
        self.assertEqual(rows["com.android.runtime"]["type"],"directory")
        self.assertEqual(rows["file.apex"]["bytes"],123)
        self.assertEqual(rows["link"]["type"],"symlink")
        self.assertNotIn(".",rows)

    def test_malformed_listing(self):
        for text in ("/12/100644/0/0/a/b/123/\n",
                     "/12/100644/0/0/file/123/\n/13/100644/0/0/file/123/\n",
                     "/12/100644/0/0/file/-1/\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    layout.parse_listing(text)

    def test_actual_ext4_flattened_module(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            tree=root/"tree"
            module=tree/"system/apex/com.android.runtime"
            module.mkdir(parents=True)
            (module/"apex_manifest.json").write_text('{"name":"com.android.runtime","version":1}')
            (module/"bin").mkdir()
            (module/"bin/linker").symlink_to("/host-should-not-be-read")
            image=root/"system.img"
            subprocess.run(["mke2fs","-q","-t","ext4","-F","-d",str(tree),str(image),"8192"],
                           check=True,capture_output=True)
            pin=hashlib.sha256(image.read_bytes()).hexdigest()
            with patch.object(layout,"checkout_sha",return_value="a"*40):
                report=layout.audit(image,pin,"a"*40)
            candidate=report["module_candidates"]["/system/apex/com.android.runtime"]
            self.assertEqual(candidate["type"],"directory")
            self.assertEqual(candidate["apex_manifest.json"]["identity"]["name"],"com.android.runtime")
            self.assertEqual(report["members"]["/system/apex/com.android.runtime/bin/linker"]["status"],"NONREGULAR")
            self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
