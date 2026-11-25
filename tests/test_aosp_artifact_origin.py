"""Local artifact origin boundaries; no actual AOSP build required."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_aosp_artifact_origin as a

SYSTEM="system/bin/galwear_property_service"
RUNTIME="apex/com.android.runtime/lib64/bionic/libc.so"

def fixtures():
    info={"sha256":"a"*64,"size_bytes":123}
    runtime={"sha256":"b"*64,"size_bytes":456,"soname":"libc.so"}
    files={SYSTEM:{**info,"source":"product:"+SYSTEM},
           RUNTIME:{**runtime,"source":"runtime:"+RUNTIME}}
    return ({"status":"INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY","files":files},
            {"nodes":{"product:"+SYSTEM:info,"runtime:"+RUNTIME:runtime}},
            {"files":{"lib64/bionic/libc.so":runtime.copy()}})

class ArtifactOriginTests(unittest.TestCase):
    def test_matching_installed_and_runtime_selection(self):
        result=a.selected(*fixtures())
        self.assertEqual(set(result),{SYSTEM,RUNTIME})
        self.assertEqual(result[RUNTIME]["sha256"],"b"*64)

    def test_intermediate_sdk_and_source_alias_rejected(self):
        for source in ("product:obj/lib/libc.so","product:system/lib64/libc.so",
                       "runtime:apex/com.android.runtime/lib64/bionic/../libc.so",
                       "product:"+RUNTIME):
            layout,g,r=fixtures()
            layout["files"][RUNTIME]["source"]=source
            with self.subTest(source=source),self.assertRaisesRegex(ValueError,"Non-installed"):
                a.selected(layout,g,r)

    def test_changed_build_graph_digest(self):
        layout,g,r=fixtures()
        layout["files"][SYSTEM]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"recorded build graph"):
            a.selected(layout,g,r)

    def test_changed_runtime_extraction(self):
        layout,g,r=fixtures()
        r["files"]["lib64/bionic/libc.so"]["soname"]="libwrong.so"
        with self.assertRaisesRegex(ValueError,"recorded APEX extraction"):
            a.selected(layout,g,r)

    def test_manifest_requires_resolved_sha_and_unique_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"manifest.xml"
            project='<project name="platform/bionic" path="bionic" revision="'+"a"*40+'"/>'
            path.write_text("<manifest>"+project+"</manifest>")
            self.assertRegex(a.manifest_digest(path),r"^[0-9a-f]{64}$")
            for raw in ("<manifest>"+project.replace("a"*40,"main")+"</manifest>",
                        "<manifest>"+project+project+"</manifest>",
                        '<!DOCTYPE manifest><manifest>'+project+'</manifest>',
                        "<manifest/>"):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    a.manifest_digest(path)

    def test_exact_image_binding(self):
        files=a.selected(*fixtures())
        origin={"status":a.STATUS,"safe_to_flash":False,"selected_files":files,
                "resolved_manifest_sha256":"manifest","runtime_apex_sha256":"apex",
                "runtime_payload_sha256":"payload"}
        image={"staged_elf_metadata":{p:{"sha256":v["sha256"]} for p,v in files.items()}}
        self.assertEqual(a.bind_system(image,origin)["runtime_payload_sha256"],"payload")
        image["staged_elf_metadata"][SYSTEM]["sha256"]="changed"
        with self.assertRaisesRegex(ValueError,"Image ELF inventory"):
            a.bind_system(image,origin)

    def test_invalid_origin_status(self):
        with self.assertRaisesRegex(ValueError,"Invalid artifact origin"):
            a.bind_system({},{"status":"PASS","safe_to_flash":False})

if __name__=="__main__":
    unittest.main()
