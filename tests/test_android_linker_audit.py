"""Synthetic ELF dependency tests; no guest execution or device access."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_linker_audit as audit


def fixture(abi="arm64", needed=(), bad_offset=False, unterminated=False, sonames=()):
    wide = abi == "arm64"
    data = bytearray(512)
    data[:7] = b"\x7fELF" + bytes([2 if wide else 1, 1, 1])
    struct.pack_into("<HH", data, 16, 3, 183 if wide else 40)
    strings = b"\0"
    offsets = []
    for name in needed:
        offsets.append(len(strings))
        strings += name.encode() + b"\0"
    soname_offsets = []
    for name in sonames:
        soname_offsets.append(len(strings))
        strings += name.encode() + b"\0"
    data[400:400+len(strings)] = strings
    tags = [(1, 9999 if bad_offset else i) for i in offsets]
    tags += [(14, 9999 if bad_offset else i) for i in soname_offsets]
    tags += [(5, 0x1000 + 400), (10, len(strings)), (1 if unterminated else 0, 0)]
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    if wide:
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x1000, 0, 512, 512, 4096)
        struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 224, 0x1000+224, 0, size, size, 8)
    else:
        struct.pack_into("<I", data, 28, 52)
        struct.pack_into("<HH", data, 42, 32, 2)
        struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0x1000, 0, 512, 512, 5, 4096)
        struct.pack_into("<IIIIIIII", data, 84, 2, 224, 0x1000+224, 0, size, size, 4, 4)
    return data


def version_fixture(abi="arm64", need=None, define=None, malformed=None):
    data = fixture(abi)
    data.extend(b"\0" * 512)
    wide = abi == "arm64"
    strings = b"\0libx.so\0VER_1\0VER_2\0"
    data[400:400 + len(strings)] = strings
    tags = [(5, 0x1000 + 400), (10, len(strings))]
    if need:
        tags += [(1, 1), (audit.DT_VERNEED, 0x1000 + 600),
                 (audit.DT_VERNEEDNUM, 1)]
        struct.pack_into("<HHIII", data, 600, 1, 1, 1, 16,
                         16 if malformed == "chain" else 0)
        struct.pack_into("<IHHII", data, 616, 0, 0, 2, strings.index(need.encode()), 0)
    if define:
        tags += [(audit.DT_VERDEF, 0x1000 + 700), (audit.DT_VERDEFNUM, 1)]
        struct.pack_into("<HHHHIII", data, 700, 1, 0, 2, 1, 0, 20, 0)
        struct.pack_into("<II", data, 720, strings.index(define.encode()), 0)
    tags += [(audit.DT_VERSYM, 0x1000 + (1024 if malformed == "versym" else 800)), (0, 0)]
    if malformed == "pair":
        tags = [pair for pair in tags if pair[0] != audit.DT_VERNEEDNUM]
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    if wide:
        struct.pack_into("<QQ", data, 96, len(data), len(data))
        struct.pack_into("<QQ", data, 152, size, size)
    else:
        struct.pack_into("<II", data, 68, len(data), len(data))
        struct.pack_into("<II", data, 100, size, size)
    return data


def symbol_fixture(abi="arm64", malformed=None):
    data = fixture(abi)
    data.extend(b"\0" * 512)
    wide = abi == "arm64"
    strings = b"\0symbol\0"
    data[400:400 + len(strings)] = strings
    entsize = 24 if wide else 16
    tags = [(5, 0x1000 + 400), (10, len(strings)),
            (audit.DT_SYMTAB, 0x1000 + 600),
            (audit.DT_SYMENT, entsize if malformed != "entry" else 1),
            (audit.DT_HASH, 0x1000 + 800),
            (audit.DT_VERSYM, 0x1000 + 900), (0, 0)]
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    struct.pack_into("<I", data, 600 + entsize, 99 if malformed == "name" else 1)
    struct.pack_into("<IIIII", data, 800, 1, 2, 2 if malformed == "bucket" else 1,
                     0, 1 if malformed == "cycle" else 0)
    struct.pack_into("<HH", data, 900, 0, 3 if malformed == "version" else 1)
    if wide:
        struct.pack_into("<QQ", data, 96, len(data), len(data))
        struct.pack_into("<QQ", data, 152, size, size)
    else:
        struct.pack_into("<II", data, 68, len(data), len(data))
        struct.pack_into("<II", data, 100, size, size)
    return data


def gnu_fixture(abi="arm64", both=False, malformed=None):
    data = symbol_fixture(abi)
    wide = abi == "arm64"
    word = 8 if wide else 4
    bits = word * 8
    h = 5381
    for b in b"symbol":
        h = (h * 33 + b) & 0xffffffff
    mask = (1 << (h % bits)) | (1 << ((h >> 5) % bits))
    addr = 840
    struct.pack_into("<IIII", data, addr, 1, 1,
                     3 if malformed == "dimensions" else 1, 5)
    struct.pack_into("<Q" if wide else "<I", data, addr + 16,
                     0 if malformed == "bloom" else mask)
    struct.pack_into("<II", data, addr + 16 + word,
                     2 if malformed == "head" else 1,
                     (h ^ 2) | 1 if malformed == "hash" else h | 1)
    tags = [(5, 0x1000 + 400), (10, len(b"\0symbol\0")),
            (audit.DT_SYMTAB, 0x1000 + 600),
            (audit.DT_SYMENT, 24 if wide else 16),
            (audit.DT_GNU_HASH, 0x1000 + addr),
            (audit.DT_VERSYM, 0x1000 + 900)]
    if both:
        tags.append((audit.DT_HASH, 0x1000 + 800))
        if malformed == "count":
            struct.pack_into("<IIIIII", data, 800, 1, 3, 1, 0, 0, 0)
    if malformed == "truncated":
        tags[4] = (audit.DT_GNU_HASH, 0x1000 + 1020)
    tags.append((0, 0))
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    if wide:
        struct.pack_into("<QQ", data, 152, size, size)
    else:
        struct.pack_into("<II", data, 100, size, size)
    return data


def classified_symbol_fixture(abi="arm64", binding=1, visibility=0, section=0,
                              version_kind=None, version_hidden=False):
    data = symbol_fixture(abi)
    wide = abi == "arm64"
    ent = 24 if wide else 16
    if wide:
        struct.pack_into("<IBBHQQ", data, 600 + ent, 1, binding << 4 | 2,
                         visibility, section, 0, 0)
    else:
        struct.pack_into("<IIIBBH", data, 600 + ent, 1, 0, 0,
                         binding << 4 | 2, visibility, section)
    if version_kind:
        strings = b"\0symbol\0libx.so\0VER_1\0"
        data[400:400 + len(strings)] = strings
        tags = [(5, 0x1000 + 400), (10, len(strings)),
                (audit.DT_SYMTAB, 0x1000 + 600), (audit.DT_SYMENT, ent),
                (audit.DT_HASH, 0x1000 + 800), (audit.DT_VERSYM, 0x1000 + 900)]
        if version_kind == "need":
            tags += [(1, 8), (audit.DT_VERNEED, 0x1000 + 700),
                     (audit.DT_VERNEEDNUM, 1)]
            struct.pack_into("<HHIII", data, 700, 1, 1, 8, 16, 0)
            struct.pack_into("<IHHII", data, 716, 0, 0, 2, 16, 0)
        else:
            tags += [(audit.DT_VERDEF, 0x1000 + 700), (audit.DT_VERDEFNUM, 1)]
            struct.pack_into("<HHHHIII", data, 700, 1, 0, 2, 1, 0, 20, 0)
            struct.pack_into("<II", data, 720, 16, 0)
        tags.append((0, 0))
        fmt = "<qQ" if wide else "<iI"
        size = len(tags) * struct.calcsize(fmt)
        for i, pair in enumerate(tags):
            struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
        if wide:
            struct.pack_into("<QQ", data, 152, size, size)
        else:
            struct.pack_into("<II", data, 100, size, size)
        struct.pack_into("<HH", data, 900, 0, 2 | (0x8000 if version_hidden else 0))
    return data


def relocation_fixture(abi="arm64", plt=False, malformed=None):
    data = symbol_fixture(abi)
    wide = abi == "arm64"
    ent = 24 if wide else 16
    rel_size = 24 if wide else 8
    addr = 940
    tags = [(5, 0x1000 + 400), (10, len(b"\0symbol\0")),
            (audit.DT_SYMTAB, 0x1000 + 600), (audit.DT_SYMENT, ent),
            (audit.DT_HASH, 0x1000 + 800)]
    if plt:
        tags += [(audit.DT_JMPREL, 0x1000 + addr), (audit.DT_PLTRELSZ, rel_size),
                 (audit.DT_PLTREL, 999 if malformed == "plt" else
                  audit.DT_RELA if wide else audit.DT_REL)]
    else:
        a, s, e = ((audit.DT_RELA, audit.DT_RELASZ, audit.DT_RELAENT) if wide else
                   (audit.DT_REL, audit.DT_RELSZ, audit.DT_RELENT))
        tags += [(a, 0x1000 + (1020 if malformed == "table" else addr)),
                 (s, rel_size - 1 if malformed == "size" else rel_size),
                 (e, 1 if malformed == "entry" else rel_size)]
    tags.append((0, 0))
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    target = 0x1000 + (1024 if malformed == "target" else 1000)
    sym = 2 if malformed == "symbol" else 1 if plt or malformed == "relative" else 0
    typ = 1026 if wide and plt else 1027 if wide else 22 if plt else 23
    if malformed == "unknown":
        typ = 250
    if wide:
        struct.pack_into("<QQq", data, addr, target, sym << 32 | typ, 0)
        struct.pack_into("<QQ", data, 152, size, size)
        struct.pack_into("<I", data, 68, 5 if malformed == "readonly" else 6)
    else:
        struct.pack_into("<II", data, addr, target, sym << 8 | typ)
        struct.pack_into("<II", data, 100, size, size)
        struct.pack_into("<I", data, 76, 5 if malformed == "readonly" else 6)
    return data


class LinkerTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)

    def put(self, path, data):
        f = self.root / path.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)

    def test_arm_and_arm64(self):
        for abi in ("arm", "arm64"):
            self.assertEqual(audit.inspect(fixture(abi, ["libc.so"]))["needed"], ["libc.so"])
            self.assertEqual(audit.inspect(fixture(abi))["abi"], abi)

    def test_bad_string_table_offset(self):
        with self.assertRaisesRegex(ValueError, "offset"):
            audit.inspect(fixture(needed=["libc.so"], bad_offset=True))

    def test_unsafe_needed(self):
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            audit.inspect(fixture(needed=["../libc.so"]))

    def test_missing_dt_null(self):
        with self.assertRaisesRegex(ValueError, "DT_NULL"):
            audit.inspect(fixture(needed=["libc.so"], unterminated=True))

    def test_transitive_and_cycle(self):
        self.put("init", fixture(needed=["liba.so"]))
        self.put("system/lib64/liba.so", fixture(needed=["libb.so"]))
        self.put("system/lib64/libb.so", fixture(needed=["liba.so"]))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertEqual(len(out["objects"]), 3)
        self.assertFalse(out["android_namespace_resolution_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_missing_and_wrong_abi(self):
        self.put("init", fixture(needed=["libc.so"]))
        self.put("system/lib64/libc.so", fixture("arm"))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["missing_candidates"][0]["needed"], "libc.so")

    def test_bionic_apex_candidate(self):
        self.put("init", fixture(needed=["libc.so"]))
        self.put("apex/com.android.runtime/lib64/bionic/libc.so", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertTrue(out["apex"]["com.android.runtime"]["expanded_tree_present"])
        self.assertFalse(out["apex_activation_verified"])

    def test_ambiguous_vendor_system(self):
        self.put("init", fixture(needed=["libx.so"]))
        for path in ("system/lib64/libx.so", "vendor/lib64/libx.so"):
            self.put(path, fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(out["ambiguous_candidates"][0]["candidates"]), 2)

    def test_executable_is_not_library_candidate(self):
        self.put("init", fixture(needed=["libx.so"]))
        child = fixture()
        struct.pack_into("<H", child, 16, 2)
        self.put("system/lib64/libx.so", child)
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["missing_candidates"][0]["needed"], "libx.so")
        self.assertTrue(any("ET_DYN" in error for error in out["errors"]))

    def test_static_shared_object_is_not_library_candidate(self):
        self.put("init", fixture(needed=["libx.so"]))
        child = fixture()
        struct.pack_into("<H", child, 56, 1)
        self.put("system/lib64/libx.so", child)
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["missing_candidates"][0]["needed"], "libx.so")

    def test_unmodeled_rpath_and_runpath_require_review(self):
        for tag in (15, 29):
            with self.subTest(tag=tag):
                child = fixture()
                struct.pack_into("<qQ", child, 224, tag, 0)
                self.put("init", child)
                out = audit.audit(self.root, ("/init",))
                self.assertEqual(out["status"], "REVIEW_REQUIRED")
                self.assertEqual(out["unsupported_search_paths"], ["/init"])
                self.assertFalse(out["safe_to_flash"])

    def test_transitive_runpath_requires_review(self):
        self.put("init", fixture(needed=["libx.so"]))
        child = fixture()
        struct.pack_into("<qQ", child, 224, 29, 0)
        self.put("system/lib64/libx.so", child)
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["unsupported_search_paths"], ["/system/lib64/libx.so"])

    def test_soname_without_needed_on_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                info = audit.inspect(fixture(abi, sonames=["libx.so"]))
                self.assertEqual(info["soname"], "libx.so")
                self.assertEqual(info["needed"], [])

    def test_invalid_soname_offset(self):
        with self.assertRaisesRegex(ValueError, "DT_SONAME offset"):
            audit.inspect(fixture(sonames=["libx.so"], bad_offset=True))

    def test_duplicate_soname(self):
        with self.assertRaisesRegex(ValueError, "Duplicate DT_SONAME"):
            audit.inspect(fixture(sonames=["libx.so", "liby.so"]))

    def test_unsafe_soname(self):
        with self.assertRaisesRegex(ValueError, "Unsafe dependency name: DT_SONAME"):
            audit.inspect(fixture(sonames=["../libx.so"]))

    def test_matching_soname(self):
        self.put("init", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture(sonames=["libx.so"]))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertEqual(out["soname_mismatches"], [])

    def test_mismatched_soname_is_review_not_missing(self):
        self.put("init", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture(sonames=["liby.so"]))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["missing_candidates"], [])
        self.assertEqual(out["soname_mismatches"], [{
            "from": "/init", "needed": "libx.so",
            "candidate": "/system/lib64/libx.so", "soname": "liby.so"}])
        self.assertFalse(out["safe_to_flash"])

    def test_version_inventory_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                need = audit.inspect(version_fixture(abi, need="VER_1"))
                self.assertEqual(need["version_needs"], [{"library": "libx.so",
                    "version": "VER_1", "weak": False, "index": 2}])
                self.assertTrue(need["versym_present"])
                definition = audit.inspect(version_fixture(abi, define="VER_1"))
                self.assertEqual(definition["version_definitions"][0]["version"], "VER_1")

    def test_invalid_version_chain(self):
        with self.assertRaisesRegex(ValueError, "chain continuation"):
            audit.inspect(version_fixture(need="VER_1", malformed="chain"))

    def test_missing_version_count_tag(self):
        with self.assertRaisesRegex(ValueError, "version tag"):
            audit.inspect(version_fixture(need="VER_1", malformed="pair"))

    def test_versym_outside_load(self):
        with self.assertRaisesRegex(ValueError, "file-backed"):
            audit.inspect(version_fixture(need="VER_1", malformed="versym"))

    def test_matching_version_definition_is_not_runtime_proof(self):
        self.put("init", version_fixture(need="VER_1"))
        self.put("system/lib64/libx.so", version_fixture(define="VER_1"))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertEqual(out["version_mismatches"], [])
        self.assertFalse(out["symbol_versions_verified"])

    def test_missing_version_definition_requires_review(self):
        self.put("init", version_fixture(need="VER_1"))
        self.put("system/lib64/libx.so", version_fixture(define="VER_2"))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["version_mismatches"][0]["version"], "VER_1")
        self.assertFalse(out["safe_to_flash"])

    def test_sysv_symbol_table_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                result = audit.inspect(symbol_fixture(abi))
                self.assertEqual(result["dynamic_symbol_count"], 2)
                self.assertEqual(result["symbol_table_status"], "SYSV_STRUCTURE_CHECKED")
                self.assertTrue(result["versym_indices_checked"])

    def test_sysv_bad_entry_size(self):
        with self.assertRaisesRegex(ValueError, "DT_SYMENT"):
            audit.inspect(symbol_fixture(malformed="entry"))

    def test_sysv_bad_bucket(self):
        with self.assertRaisesRegex(ValueError, "hash index"):
            audit.inspect(symbol_fixture(malformed="bucket"))

    def test_sysv_cyclic_chain(self):
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            audit.inspect(symbol_fixture(malformed="cycle"))

    def test_dynamic_symbol_bad_name(self):
        with self.assertRaisesRegex(ValueError, "symbol name"):
            audit.inspect(symbol_fixture(malformed="name"))

    def test_unknown_versym_index(self):
        with self.assertRaisesRegex(ValueError, "unknown version index"):
            audit.inspect(symbol_fixture(malformed="version"))

    def test_gnu_hash_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                result = audit.inspect(gnu_fixture(abi))
                self.assertEqual(result["dynamic_symbol_count"], 2)
                self.assertEqual(result["symbol_table_status"], "GNU_STRUCTURE_CHECKED")
                self.assertTrue(result["versym_indices_checked"])

    def test_both_hash_tables_agree(self):
        result = audit.inspect(gnu_fixture(both=True))
        self.assertEqual(result["symbol_table_status"], "SYSV_AND_GNU_STRUCTURE_CHECKED")

    def test_hash_counts_disagree(self):
        with self.assertRaisesRegex(ValueError, "counts disagree"):
            audit.inspect(gnu_fixture(both=True, malformed="count"))

    def test_gnu_invalid_dimensions(self):
        with self.assertRaisesRegex(ValueError, "GNU hash dimensions"):
            audit.inspect(gnu_fixture(malformed="dimensions"))

    def test_gnu_invalid_bucket_start(self):
        with self.assertRaisesRegex(ValueError, "noncontiguous"):
            audit.inspect(gnu_fixture(malformed="head"))

    def test_gnu_wrong_symbol_hash(self):
        with self.assertRaisesRegex(ValueError, "match symbol name"):
            audit.inspect(gnu_fixture(malformed="hash"))

    def test_gnu_missing_bloom_bits(self):
        with self.assertRaisesRegex(ValueError, "Bloom filter"):
            audit.inspect(gnu_fixture(malformed="bloom"))

    def test_gnu_truncated_header(self):
        with self.assertRaisesRegex(ValueError, "file-backed"):
            audit.inspect(gnu_fixture(malformed="truncated"))

    def test_global_import_and_export_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                imported = audit.inspect(classified_symbol_fixture(abi))
                self.assertEqual(imported["symbol_imports"][0]["name"], "symbol")
                self.assertFalse(imported["symbol_imports"][0]["weak"])
                exported = audit.inspect(classified_symbol_fixture(abi, section=1))
                self.assertEqual(exported["symbol_exports"][0]["name"], "symbol")
                self.assertEqual(exported["symbol_imports"], [])

    def test_weak_import_and_export(self):
        for section, key in ((0, "symbol_imports"), (1, "symbol_exports")):
            self.assertTrue(audit.inspect(classified_symbol_fixture(
                binding=2, section=section))[key][0]["weak"])

    def test_local_hidden_and_internal_not_exported(self):
        for binding, visibility in ((0, 0), (1, 1), (1, 2)):
            info = audit.inspect(classified_symbol_fixture(
                binding=binding, visibility=visibility, section=1))
            self.assertEqual(info["symbol_exports"], [])

    def test_protected_definition_exported(self):
        info = audit.inspect(classified_symbol_fixture(visibility=3, section=1))
        self.assertEqual(info["symbol_exports"][0]["visibility"], 3)

    def test_versioned_import(self):
        info = audit.inspect(classified_symbol_fixture(version_kind="need"))
        record = info["symbol_imports"][0]
        self.assertEqual(record["version"], "VER_1")
        self.assertEqual(record["version_library"], "libx.so")

    def test_nondefault_versioned_export(self):
        info = audit.inspect(classified_symbol_fixture(
            section=1, version_kind="define", version_hidden=True))
        record = info["symbol_exports"][0]
        self.assertEqual(record["version"], "VER_1")
        self.assertTrue(record["version_hidden"])

    def test_nonstandard_symbol_requires_review(self):
        self.put("init", classified_symbol_fixture(binding=10, section=1))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["unsupported_symbol_objects"], ["/init"])
        self.assertFalse(out["symbol_resolution_verified"])

    def test_symbol_provider_in_direct_dependency(self):
        root = audit.inspect(classified_symbol_fixture())
        lib = audit.inspect(classified_symbol_fixture(section=1))
        out = audit.symbol_candidates({"init": root, "lib": lib},
                                      {"init": {"libx.so": ["lib"]}})
        self.assertEqual(out["matched"], 1)
        self.assertEqual(out["missing_strong"], [])

    def test_symbol_provider_in_transitive_cycle(self):
        root = audit.inspect(classified_symbol_fixture())
        lib = audit.inspect(classified_symbol_fixture(section=1))
        out = audit.symbol_candidates({"init": root, "bridge": lib, "lib": lib},
                                      {"init": {"a": ["bridge"]},
                                       "bridge": {"b": ["lib"]}, "lib": {"c": ["bridge"]}})
        self.assertEqual(out["ambiguous"][0]["providers"], ["bridge", "lib"])

    def test_unrelated_target_does_not_provide_symbol(self):
        root = audit.inspect(classified_symbol_fixture())
        lib = audit.inspect(classified_symbol_fixture(section=1))
        out = audit.symbol_candidates({"init": root, "unrelated": lib}, {})
        self.assertEqual(len(out["missing_strong"]), 1)
        self.assertEqual(out["matched"], 0)

    def test_missing_weak_symbol_is_separate(self):
        root = audit.inspect(classified_symbol_fixture(binding=2))
        out = audit.symbol_candidates({"init": root}, {})
        self.assertEqual(len(out["missing_weak"]), 1)
        self.assertEqual(out["missing_strong"], [])

    def test_incomplete_dependency_does_not_prove_missing_symbol(self):
        root = audit.inspect(classified_symbol_fixture())
        out = audit.symbol_candidates({"init": root, "lib": None},
                                      {"init": {"libx.so": ["lib"]}})
        self.assertEqual(len(out["incomplete"]), 1)
        self.assertEqual(out["missing_strong"], [])

    def test_nondefault_export_does_not_match_unversioned_import(self):
        root = audit.inspect(classified_symbol_fixture())
        lib = audit.inspect(classified_symbol_fixture(
            section=1, version_kind="define", version_hidden=True))
        out = audit.symbol_candidates({"init": root, "lib": lib},
                                      {"init": {"libx.so": ["lib"]}})
        self.assertEqual(len(out["missing_strong"]), 1)

    def test_versioned_import_matches_named_provider(self):
        root = audit.inspect(classified_symbol_fixture(version_kind="need"))
        lib = audit.inspect(classified_symbol_fixture(
            section=1, version_kind="define", version_hidden=True))
        out = audit.symbol_candidates({"init": root, "lib": lib, "other": lib},
                                      {"init": {"libx.so": ["lib"], "other.so": ["other"]}})
        self.assertEqual(out["matched"], 1)
        self.assertEqual(out["ambiguous"], [])

    def test_wrong_abi_cannot_provide_symbol(self):
        root = audit.inspect(classified_symbol_fixture("arm64"))
        lib = audit.inspect(classified_symbol_fixture("arm", section=1))
        out = audit.symbol_candidates({"init": root, "lib": lib},
                                      {"init": {"libx.so": ["lib"]}})
        self.assertEqual(len(out["missing_strong"]), 1)

    def test_rel_and_rela_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                info = audit.inspect(relocation_fixture(abi))["relocations"]
                self.assertEqual(info["tables"][0]["count"], 1)
                self.assertEqual(info["tables"][0]["kind"], "RELA" if abi == "arm64" else "REL")
                self.assertTrue(info["symbol_indices_checked"])
                self.assertFalse(info["relocations_applied"])

    def test_plt_relocations(self):
        for abi in ("arm", "arm64"):
            self.assertEqual(audit.inspect(relocation_fixture(abi, plt=True))[
                "relocations"]["tables"][0]["kind"], "PLT")

    def test_invalid_relocation_entry_and_size(self):
        for case in ("entry", "size"):
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, "relocation.*size"):
                audit.inspect(relocation_fixture(malformed=case))

    def test_invalid_relocation_symbol(self):
        with self.assertRaisesRegex(ValueError, "symbol index out of bounds"):
            audit.inspect(relocation_fixture(malformed="symbol"))

    def test_relative_relocation_nonzero_symbol(self):
        with self.assertRaisesRegex(ValueError, "nonzero symbol"):
            audit.inspect(relocation_fixture(malformed="relative"))

    def test_relocation_outside_load_memory(self):
        with self.assertRaisesRegex(ValueError, "outside PT_LOAD"):
            audit.inspect(relocation_fixture(malformed="target"))

    def test_truncated_relocation_table(self):
        with self.assertRaisesRegex(ValueError, "file-backed"):
            audit.inspect(relocation_fixture(malformed="table"))

    def test_invalid_plt_encoding(self):
        with self.assertRaisesRegex(ValueError, "DT_PLTREL"):
            audit.inspect(relocation_fixture(plt=True, malformed="plt"))

    def test_unknown_type_and_readonly_target_require_review(self):
        for case in ("unknown", "readonly"):
            with self.subTest(case=case):
                self.put("init", relocation_fixture(malformed=case))
                out = audit.audit(self.root, ("/init",))
                self.assertEqual(out["status"], "REVIEW_REQUIRED")
                self.assertEqual(out["relocation_review_objects"], ["/init"])

    def test_symlink_alias_not_ambiguous(self):
        self.put("init", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture())
        p = self.root / "vendor/lib64/libx.so"
        p.parent.mkdir(parents=True)
        p.symlink_to("/system/lib64/libx.so")
        self.assertEqual(audit.audit(self.root, ("/init",))["status"], "CANDIDATES_FOUND_ONLY")


if __name__ == "__main__":
    unittest.main()
