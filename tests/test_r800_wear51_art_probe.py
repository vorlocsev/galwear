"""Synthetic tests for ART probe paths and namespace construction."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_wear51_art_probe as probe

def objects():
    names={probe.LINKER:"ld-android.so",probe.DEX:None,probe.STUB:"ld-android.so",
           "runtime:/lib/bionic/libc.so":"libc.so","runtime:/lib/bionic/libm.so":"libm.so",
           "runtime:/lib/bionic/libdl.so":"libdl.so","art:/lib/libbase.so":"libbase.so",
           "system:/system/lib/libbase.so":"libbase.so","statsd:/lib/libstatspull.so":"libstatspull.so",
           "statsd:/lib/libstatssocket.so":"libstatssocket.so"}
    return {k:{"soname":v} for k,v in names.items()}

class ArtProbeTests(unittest.TestCase):
    def test_separate_locations(self):
        self.assertEqual(probe.guest_path("art:/lib/libbase.so"),"/apex/com.android.art/lib/libbase.so")
        self.assertEqual(probe.guest_path("system:/system/lib/libbase.so"),"/system/lib/libbase.so")

    def test_reject_paths(self):
        for key in ("host:/lib/a.so","art:/lib/../a.so","system:/lib/a.so","runtime:/bin/evil.so"):
            with self.subTest(key=key),self.assertRaises(ValueError):
                probe.guest_path(key)

    def test_config_preserves_namespaces(self):
        cfg=probe.config(objects())
        self.assertIn("namespace.default.search.paths = /apex/com.android.art/lib\n",cfg)
        self.assertIn("namespace.system.search.paths = /system/lib\n",cfg)
        self.assertIn("namespace.default.link.statsd.shared_libs = libstatspull.so:libstatssocket.so\n",cfg)
        self.assertIn("namespace.default.link.system.shared_libs = libbase.so\n",cfg)
        self.assertNotIn("allow_all_shared_libs",cfg)

    def test_optional_original_i18n_namespace(self):
        data=objects()
        self.assertNotIn("namespace.i18n.",probe.config(data))
        data["i18n:/lib/libicu.so"]={"soname":"libicu.so"}
        cfg=probe.config(data)
        self.assertEqual(probe.guest_path("i18n:/lib/libicu.so"),"/apex/com.android.i18n/lib/libicu.so")
        self.assertIn("namespace.default.link.i18n.shared_libs = libicu.so\n",cfg)
        self.assertIn("namespace.i18n.search.paths = /apex/com.android.i18n/lib\n",cfg)
        self.assertNotIn("allow_all_shared_libs",cfg)
        with self.assertRaises(ValueError):
            probe.guest_path("i18n:/lib/../libicu.so")

    def test_optional_nnapi_namespace(self):
        data=objects()
        self.assertNotIn("namespace.neuralnetworks.",probe.config(data))
        data["neuralnetworks:/lib/libneuralnetworks.so"]={"soname":"libneuralnetworks.so"}
        cfg=probe.config(data,vm_oat=True)
        self.assertEqual(probe.guest_path("neuralnetworks:/lib/libneuralnetworks.so"),"/apex/com.android.neuralnetworks/lib/libneuralnetworks.so")
        self.assertIn("namespace.default.link.neuralnetworks.shared_libs = libneuralnetworks.so\n",cfg)
        self.assertIn("namespace.neuralnetworks.search.paths = /apex/com.android.neuralnetworks/lib\n",cfg)
        self.assertNotIn("allow_all_shared_libs",cfg)
        with self.assertRaises(ValueError):
            probe.guest_path("neuralnetworks:/lib64/libneuralnetworks.so")

    def test_system_vm_imports_only_needed_unique_apex_providers(self):
        data=objects()
        data["system:/system/lib/libharfbuzz_ng.so"]={"soname":"libharfbuzz_ng.so","needed":["libicu.so","libc.so","libstatspull.so","libambiguous.so"]}
        data["i18n:/lib/libicu.so"]={"soname":"libicu.so"}
        data["i18n:/lib/libicuuc.so"]={"soname":"libicuuc.so"}
        data["i18n:/lib/libambiguous.so"]={"soname":"libambiguous.so"}
        data["neuralnetworks:/lib/libambiguous.so"]={"soname":"libambiguous.so"}
        baseline=probe.config(data)
        self.assertNotIn("namespace.system.link.i18n.",baseline)
        cfg=probe.config(data,vm_oat=True)
        self.assertIn("namespace.system.links = runtime,i18n,statsd\n",cfg)
        self.assertIn("namespace.system.link.i18n.shared_libs = libicu.so\n",cfg)
        self.assertIn("namespace.system.link.statsd.shared_libs = libstatspull.so\n",cfg)
        self.assertNotIn("namespace.system.link.neuralnetworks.",cfg)
        self.assertNotIn("allow_all_shared_libs",cfg)

    def test_vm_oat_export_is_scoped_to_private_boot_directory(self):
        baseline=probe.config(objects())
        self.assertNotIn("namespace.system.visible",baseline)
        self.assertNotIn("permitted.paths",baseline)
        cfg=probe.config(objects(),vm_oat=True)
        self.assertIn("namespace.system.visible = true\n",cfg)
        self.assertIn("namespace.system.permitted.paths = /data/arm\n",cfg)
        self.assertEqual(cfg.replace("namespace.system.visible = true\n","").replace("namespace.system.permitted.paths = /data/arm\n",""),baseline)
        self.assertNotIn("allow_all_shared_libs",cfg)

    def test_logdw_record(self):
        packet=b"\0"*11+b"\x06dex2oat\0Usage: dex2oat [options]...\0"
        self.assertEqual(probe.decode_log_record(packet),
                         {"priority":6,"tag":"dex2oat","message":"Usage: dex2oat [options]..."})
        self.assertIsNone(probe.decode_log_record(b"bad"))

    def test_usage_error_requires_actual_log(self):
        err=probe.USAGE_ERROR+"\n"
        status,_,_=probe.evaluate_case("dex2oat-help",1,"",err,[],False,False,{})
        self.assertEqual(status,"REVIEW_REQUIRED")
        records=[{"message":"Usage: dex2oat [options]..."}]
        status,_,_=probe.evaluate_case("dex2oat-help",1,"",err,records,False,False,{})
        self.assertEqual(status,"ARGUMENT_HANDLER_OBSERVED")
        status,_,_=probe.evaluate_case("dex2oat-invalid",1,"",err,records,False,False,{})
        self.assertEqual(status,"REVIEW_REQUIRED")
        records.append({"message":"Unknown argument "+probe.INVALID_OPTION})
        status,_,_=probe.evaluate_case("dex2oat-invalid",1,"",err,records,False,False,{})
        self.assertEqual(status,"ARGUMENT_HANDLER_OBSERVED")
        status,_,_=probe.evaluate_case("dex2oat-invalid",132,"",err,records,False,False,{})
        self.assertEqual(status,"REVIEW_REQUIRED")

    def test_linker_list_requires_separate_providers(self):
        paths=["/apex/com.android.art/lib/libart.so","/apex/com.android.art/lib/libc++.so",
               "/system/lib/libc++.so","/apex/com.android.runtime/lib/bionic/libc.so",
               "/apex/com.android.os.statsd/lib/libstatspull.so",
               "/apex/com.android.os.statsd/lib/libstatssocket.so"]
        out="".join(p.rsplit("/",1)[1]+" => "+p+" (0x1234)\n" for p in paths)
        staged=dict.fromkeys(paths,"fixture")
        status,_,_=probe.evaluate_case("linker-list",0,out,"",[],False,False,staged)
        self.assertEqual(status,"MARKER_PASS")
        del staged[paths[1]]
        status,_,_=probe.evaluate_case("linker-list",0,out,"",[],False,False,staged)
        self.assertEqual(status,"REVIEW_REQUIRED")

    def test_proc_tmpfs_stays_private(self):
        cmd=probe.sandbox_command("/host/qemu","bwrap",Path("/private/guest"),
                                  "/private/log",["/apex/com.android.art/bin/dex2oat32"])
        self.assertIn("--unshare-all",cmd)
        self.assertIn("--clearenv",cmd)
        self.assertEqual(cmd[cmd.index("--proc")+1],"/proc")
        self.assertEqual(cmd[cmd.index("--tmpfs")+1],"/tmp")
        self.assertEqual(cmd[cmd.index("--setenv")+1:cmd.index("--setenv")+3],["TMPDIR","/tmp"])
        self.assertNotIn("--bind",cmd)
        self.assertNotIn("--share-net",cmd)
        self.assertEqual(cmd.count("--ro-bind"),3)

    def test_boot_output_only_writable_host_bind(self):
        cmd=probe.sandbox_command("/host/qemu","bwrap",Path("/private/guest"),
                                  "/private/log",["/apex/com.android.art/bin/dex2oat32"],
                                  Path("/private/output"))
        self.assertEqual(cmd.count("--bind"),1)
        i=cmd.index("--bind")
        self.assertEqual(cmd[i+1:i+3],["/private/output","/data"])
        self.assertEqual(cmd[cmd.index("--tmpfs")+1],"/tmp")

    def test_missing_statsd(self):
        data=objects()
        del data["statsd:/lib/libstatspull.so"]
        with self.assertRaisesRegex(ValueError,"StatsD"):
            probe.config(data)

if __name__=="__main__":
    unittest.main()
