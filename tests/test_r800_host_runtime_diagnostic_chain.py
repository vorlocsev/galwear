"""Synthetic saved runtime diagnostics tests; never invoke host probes."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_host_runtime_diagnostic_chain as chain

PIN="a"*64
ROOT="/usr/bin/python3.12"
LIB="/usr/lib/x86_64-linux-gnu/libc.so.6"
LOADER="/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"


class RuntimeChainTests(unittest.TestCase):
    def setUp(self):
        self.elf={"roots":["python3"],"objects":{
            ROOT:{"needed":["libc.so.6"],"interpreter":chain.LOADER},
            LIB:{"needed":[],"interpreter":None},
            LOADER:{"needed":[],"interpreter":None}},
            "bindings":{"python3":ROOT,"libc.so.6":LIB,chain.LOADER:LOADER}}
        self.loader={"host_elf_lock_sha256":PIN,"tools":{"python3":{
            "status":"GLIBC_LIST_MATCH_ONLY","providers":{"libc.so.6":LIB,chain.LOADER:LOADER},
            "vdso_observed":True}}}
        self.lock={"python_version":"3.12.3"}
        files={"json.py":{"kind":"regular","bytes":1,"sha256":PIN}}
        tree_hash=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(",",":"),
                                             ensure_ascii=True).encode()).hexdigest()
        self.runtime={"python_version":"3.12.3","stdlib_root":"/usr/lib/python3.12",
                      "stdlib":{"files":files,"file_count":1,"problems":[],
                                "regular_bytes":1,"tree_sha256":tree_hash},
                      "native_extensions":{"status":"HOST_STATIC_CANDIDATES_ONLY","problems":[],
                          "objects":{},"bindings":{},"loader_search_verified":False,
                          "runtime_verified":False,"host_isolated":False,"safe_to_flash":False}}
        self.sources={n:{"sha256":PIN} for n in chain.TARGETS}
        self.imports={"python_runtime_lock_sha256":PIN,"runtime_inventory_status":chain.PY_STATUS,
                      "targets":list(chain.TARGETS),"flags":dict(chain.FLAGS),
                      "sys_path":list(chain.PATHS),
                      "modules":{n:{"kind":"tracked_source","sha256":PIN} for n in chain.TARGETS}}
        self.imports["modules"]["json"]={"kind":"stdlib","path":"json.py","sha256":PIN,
                                         "cached_candidate_sha256":None}

    def python(self):
        chain.review_python(self.lock,self.runtime,self.imports,PIN,self.sources)

    def test_exact_loader(self):
        chain.review_loader(self.elf,self.loader,PIN)

    def test_loader_missing_provider(self):
        del self.loader["tools"]["python3"]["providers"]["libc.so.6"]
        with self.assertRaisesRegex(ValueError,"Missing saved loader provider"):
            chain.review_loader(self.elf,self.loader,PIN)

    def test_wrong_elf_pin(self):
        with self.assertRaisesRegex(ValueError,"ELF pin mismatch"):
            chain.review_loader(self.elf,self.loader,"b"*64)

    def test_exact_python(self):
        self.python()

    def test_changed_tree(self):
        self.runtime["stdlib"]["files"]["json.py"]["sha256"]="b"*64
        with self.assertRaisesRegex(ValueError,"tree identity mismatch"):
            self.python()

    def test_wrong_import_pin(self):
        self.imports["python_runtime_lock_sha256"]="b"*64
        with self.assertRaisesRegex(ValueError,"import report binding mismatch"):
            self.python()

    def test_wrong_tracked_source(self):
        self.sources[chain.TARGETS[0]]["sha256"]="b"*64
        with self.assertRaisesRegex(ValueError,"Tracked Python source pin mismatch"):
            self.python()

    def test_unpinned_module(self):
        self.imports["modules"]["json"]["path"]="unknown.py"
        with self.assertRaisesRegex(ValueError,"module source pin mismatch"):
            self.python()


if __name__=="__main__":
    unittest.main()
