"""Static minimum graphics exports; no dlopen, EGL calls or device access."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_graphics_inventory as mod


def symbol(name, typ=2, hidden=False, binding=1, visibility=0):
    return {"name":name,"type":typ,"version_hidden":hidden,
            "binding":binding,"visibility":visibility}


def info(symbols, abi="arm", count=20):
    return {"abi":abi,"dynamic_symbol_count":count,"symbol_exports":symbols}


def library(path, names, abi="arm"):
    result=info([symbol(name) for name in names],abi)
    result["entrypoints"]=mod.entrypoint_evidence(path,result)
    return result


class GraphicsEntrypointTests(unittest.TestCase):
    def test_minimum_egl_exports(self):
        path="/vendor/lib/egl/libEGL_mali.so"
        out=mod.entrypoint_evidence(path,info([symbol(n) for n in mod.ENTRYPOINTS["libEGL"]]))
        self.assertEqual(out["status"],"STATIC_MINIMUM_EXPORTS_ONLY")
        self.assertFalse(out["runtime_resolution_verified"])

    def test_hidden_version_and_wrong_symbol_types(self):
        path="/vendor/lib/egl/libEGL_mali.so"
        out=mod.entrypoint_evidence(path,info([symbol("eglInitialize",hidden=True),
            symbol("eglGetDisplay",1),symbol("eglChooseConfig",0),
            symbol("eglTerminate",visibility=2)]))
        self.assertEqual(out["status"],"REVIEW_REQUIRED")
        self.assertEqual(out["untyped_candidates"],["eglChooseConfig"])
        self.assertEqual(out["incompatible_candidates"],
                         ["eglGetDisplay","eglInitialize","eglTerminate"])

    def test_uninspected_symbols(self):
        out=mod.entrypoint_evidence("/vendor/lib/egl/libGLES.so",info([],count=None))
        self.assertEqual(out["status"],"UNINSPECTED")

    def test_legacy_hmi_object_not_function(self):
        path="/vendor/lib/hw/gralloc.exynos.so"
        self.assertEqual(mod.entrypoint_evidence(path,info([symbol("HMI",1)]))["status"],
                         "STATIC_MINIMUM_EXPORTS_ONLY")
        self.assertEqual(mod.entrypoint_evidence(path,info([symbol("HMI",2)]))["status"],
                         "REVIEW_REQUIRED")

    def test_private_mali_no_policy(self):
        out=mod.entrypoint_evidence("/vendor/lib/egl/libMali.so",info([]))
        self.assertEqual(out["status"],"NO_ENTRYPOINT_POLICY")

    def test_split_group_and_missing_export(self):
        egl="/vendor/lib/egl/libEGL_mali.so"
        gl="/vendor/lib/egl/libGLESv2_mali.so"
        libs={egl:library(egl,mod.ENTRYPOINTS["libEGL"]),
              gl:library(gl,mod.ENTRYPOINTS["libGLESv2"])}
        groups={"status":"STATIC_EGL_DRIVER_GROUP_ONLY","groups":[{
            "directory":"/vendor/lib/egl","suffix":"mali","structurally_complete":True,
            "libraries":{"libEGL":egl,"libGLESv2":gl}}]}
        out=mod.graphics_entrypoints(libs,groups,"arm")
        self.assertEqual(out["status"],"STATIC_GRAPHICS_MINIMUM_EXPORTS_ONLY")
        self.assertTrue(out["groups"][0]["split_minimum_exports"])
        libs[gl]=library(gl,mod.ENTRYPOINTS["libGLESv2"][:-1])
        self.assertEqual(mod.graphics_entrypoints(libs,groups,"arm")["review_libraries"],[gl])

    def test_combined_group_and_abi(self):
        path="/vendor/lib64/egl/libGLES_mali.so"
        libs={path:library(path,set(mod.ENTRYPOINTS["libEGL"]+mod.ENTRYPOINTS["libGLESv2"]),"arm64")}
        groups={"status":"STATIC_EGL_DRIVER_GROUP_ONLY","groups":[{
            "directory":"/vendor/lib64/egl","suffix":"mali","structurally_complete":True,
            "libraries":{"libGLES":path}}]}
        self.assertTrue(mod.graphics_entrypoints(libs,groups,"arm64")["groups"][0]["combined_minimum_exports"])
        self.assertEqual(mod.graphics_entrypoints(libs,groups,"arm")["status"],"REVIEW_REQUIRED")
