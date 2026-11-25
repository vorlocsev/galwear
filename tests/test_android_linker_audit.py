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


def sleb128(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
        out.append(byte if done else byte | 128)
        if done:
            return bytes(out)


def aps2_fixture(values, signature=b"APS2", trailing=b""):
    return signature + b"".join(sleb128(v) for v in values) + trailing


def inspect_aps2(blob, abi="arm64", rela=True, symbol_count=2):
    a, s = ((audit.DT_ANDROID_RELA, audit.DT_ANDROID_RELASZ) if rela else
            (audit.DT_ANDROID_REL, audit.DT_ANDROID_RELSZ))
    return audit.relocation_inventory({a: [0x1000], s: [len(blob)]},
        blob, [(0x1000, 0, len(blob))], [(0x2000, 256, 6)],
        2 if abi == "arm64" else 1, symbol_count)


def inspect_relr(entries, abi="arm64", android=False, malformed=None, writable=True):
    wide = abi == "arm64"
    word = 8 if wide else 4
    data = struct.pack("<" + str(len(entries)) + ("Q" if wide else "I"), *entries)
    a, s, e = ((audit.DT_ANDROID_RELR, audit.DT_ANDROID_RELRSZ, audit.DT_ANDROID_RELRENT)
               if android else (audit.DT_RELR, audit.DT_RELRSZ, audit.DT_RELRENT))
    tags = {a: [0x1000], s: [len(data)], e: [word]}
    if malformed == "size":
        tags[s] = [len(data) - 1]
    elif malformed == "entry":
        tags[e] = [word * 2]
    elif malformed == "missing":
        del tags[e]
    elif malformed == "truncated":
        tags[s] = [len(data) + word]
    elif malformed == "both":
        tags.update({audit.DT_ANDROID_RELR: [0x1000],
                     audit.DT_ANDROID_RELRSZ: [len(data)], audit.DT_ANDROID_RELRENT: [word]})
    return audit.relocation_inventory(tags, data, [(0x1000, 0, len(data))],
        [(0x2000, 0x1000, 6 if writable else 4)], 2 if wide else 1, None)


def tls_fixture(abi="arm64", malformed=None):
    data = symbol_fixture(abi)
    wide = abi == "arm64"
    old, entsize = (64, 56) if wide else (52, 32)
    headers = bytes(data[old:old + 2 * entsize])
    data.extend(headers + bytes(entsize))
    pos = 1024 + 2 * entsize
    addr = 0x1000 + 960
    filesz = 8
    memsz = 32
    align = 8
    if malformed == "alignment":
        align = 3
    elif malformed == "file":
        filesz = 64
    elif malformed == "memory":
        memsz = 128
    elif malformed == "mapping":
        addr += 8
    if wide:
        struct.pack_into("<Q", data, 32, 1024)
        struct.pack_into("<H", data, 56, 3)
        struct.pack_into("<IIQQQQQQ", data, pos, 7, 4, 960, addr, 0, filesz, memsz, align)
        struct.pack_into("<IBBHQQ", data, 624, 1, 0x16, 0, 1,
                         32 if malformed == "symbol" else 0, 4)
    else:
        struct.pack_into("<I", data, 28, 1024)
        struct.pack_into("<H", data, 44, 3)
        struct.pack_into("<IIIIIIII", data, pos, 7, 960, addr, 0, filesz, memsz, 4, align)
        struct.pack_into("<IIIBBH", data, 616, 1,
                         32 if malformed == "symbol" else 0, 4, 0x16, 0, 1)
    return data


def inspect_tls_relocation(abi, typ, target=0x2000, tls_indices=frozenset({1}),
                           span=16, sym=1):
    wide = abi == "arm64"
    data = (struct.pack("<QQq", target, sym << 32 | typ, 0) if wide else
            struct.pack("<II", target, sym << 8 | typ))
    tags = ({audit.DT_RELA: [0x1000], audit.DT_RELASZ: [len(data)],
             audit.DT_RELAENT: [len(data)]} if wide else
            {audit.DT_REL: [0x1000], audit.DT_RELSZ: [len(data)],
             audit.DT_RELENT: [len(data)]})
    return audit.relocation_inventory(tags, data, [(0x1000, 0, len(data))],
        [(0x2000, span, 6)], 2 if wide else 1, 2, tls_indices)


NAMESPACE_CONFIG = """dir.system = /system/bin
dir.vendor = /vendor/bin
[system]
additional.namespaces = vendor
namespace.default.isolated = true
namespace.default.search.paths = /system/${LIB}
namespace.default.search.paths += /system_ext/${LIB}
namespace.default.links = vendor
namespace.default.link.vendor.shared_libs = libx.so:liby.so
namespace.vendor.isolated = true
namespace.vendor.search.paths = /vendor/${LIB}
namespace.vendor.permitted.paths = /vendor
[vendor]
namespace.default.search.paths = /vendor/${LIB}
"""


def apex_pb(name="com.android.runtime", version=1):
    raw = name.encode()
    return bytes([10, len(raw)]) + raw + bytes([16, version])


def apex_zip(path, manifest=None, aligned=True, ext4=True, compressed=False):
    import zipfile
    manifest = apex_pb() if manifest is None else manifest
    with zipfile.ZipFile(path, "w") as z:
        image = bytearray(4096)
        if ext4:
            image[1080:1082] = b"\x53\xef"
        info = zipfile.ZipInfo("apex_payload.img")
        info.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
        if aligned:
            padding = 4096 - 30 - len(info.filename) - 4
            info.extra = struct.pack("<HH", 0xcafe, padding) + bytes(padding)
        z.writestr(info, image)
        z.writestr("apex_manifest.pb", manifest)
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("apex_pubkey", b"key")


def avb_fixture(case=None):
    import hashlib
    key = struct.pack(">II", 2048, 0) + bytes(512)
    body = (struct.pack(">IQQQIIIQQ", 1, 4096, 4096, 4096, 4096, 4096, 0, 0, 0)
            + b"sha256".ljust(32, b"\0") + struct.pack(">IIII", 0, 0, 32, 0)
            + bytes(60) + bytes(32))
    if case == "geometry":
        body = bytearray(body)
        struct.pack_into(">Q", body, 12, 32768)
        body = bytes(body)
    body += bytes((-len(body)) % 8)
    descriptor = struct.pack(">QQ", 1, len(body)) + body
    if case == "descriptor":
        descriptor = struct.pack(">QQ", 1, 9999) + body
    aux = key + descriptor
    aux += bytes((-len(aux)) % 64)
    header = bytearray(256)
    header[:4] = b"AVB0"
    struct.pack_into(">IIQQI", header, 4, 1, 0, 320, len(aux), 1)
    struct.pack_into(">11QII", header, 32, 0, 32, 32, 256, 0, len(key),
                     0, 0, len(key), len(descriptor), 0, 0, 0)
    if case == "block":
        struct.pack_into(">Q", header, 64, len(aux) + 1)
    digest = hashlib.sha256(header + aux).digest()
    if case == "digest":
        digest = bytes(32)
    blob = bytes(header) + digest + bytes(288) + aux
    footer = b"AVBf" + struct.pack(">IIQQQ", 1, 0, 4096,
                                   999999 if case == "footer" else 8192, len(blob)) + bytes(28)
    payload = bytes(8192) + blob
    payload += bytes(16384 - 64 - len(payload)) + footer
    return payload, key


# Public-only RSA fixture generated independently with cryptography/OpenSSL.
AVB_RSA_N = int(
    "d5bb53d50d85fe7ecd6625e37c43693736fbe6d0024f58d14a078c5e65d8b64db154714a851068540a1f764a7ee929bae5a74a157ef727ca8204128518df25b9a8a5f3189dab939b06e5ef228bb71443c193b5f9b18d0432c5c06ad1f60089e00a16fc80f35cc66ec9686fa541b07efe02dacf614f0343d87029e58abaa4a42c12681e591d7f3b3ad3d23414d81c794790ed0d9916bf6403345f4f4328bae4253a6dc3bb3022c1e465e516bc74356b4a923b1be7cdf050891d9ad27ca5ffc2ea9ca75273bcf416e0f67f1e2dfc2c494414a1e9bacfa8dff5bd21c42cfeafd5d8e9a56ab471a62c932f0b59653cbbb24855f18dbe9797cd35d73a570ec9b14f7b", 16)
AVB_RSA_SIGNATURES = {
    1: bytes.fromhex("bd658e4ed3f9ae50d4b3c5fb58de22d86facf930f3f6b1ad6474ed0c390f194cc179e66242dc48d8bd85c952108b19be2d935989b6c109694458f2bc4d78bd6daa2ea0d53ba47d13f403c440b5237a73aaec3d0bbd22b5a660cc6313d6c8a83cc331e48340a973c657efa593f4c30a9f1df4376868be7a87190a7d1e7dc921619770c70bbdaf1950362d09c23b48b6ac26c9f46930f90b896971eb9fe9f2c4187f26f6693c56b6370c6dd1a64a6cda9f721272184e6ee83e07219a27f7e1dc9b68add90b4b42b0a7b72dbae50e4c67c87eced894802ec951210366bc0fffa872bcab2a54f9c06450e1f7d9702814c2afd65a458d430e3df07ee60ea495a504bb"),
    4: bytes.fromhex("c7b5798c8a2c2122f9308d6de38fa840f77e56fe2362507b06aa5a1ea273894ffbb06d0e2cfc3be606de7f6519554795926436faf6feb3e474ca492c7968f711559030b34e496373a27b0c71f031e5b8d573ea2580e89f98974b3fb4a182d5d38f5152af6e93fc3260315ce38a90f1bee2e6f92eaa8bb5922c4496f5de13d6e74f75c73e57e2491eafdc10544f0639a53c27ed5367285c6c1a3568b077ae23538dc6da88f225c7cc7ed06d5de2ba12ab4b206d9adbd18f04c513a05a220da04471aa3c9310cf5b6c44aa2ac9aee06cdc048d327e6371522dddc71edde42895421a1a22ad72f7942162a0faddbf189ac3e752a0da72cbb4576f6cbe87bf4fadb3"),
}


def signed_avb_fixture(algorithm=1):
    import hashlib
    payload, _ = avb_fixture()
    key = (struct.pack(">II", 2048, -pow(AVB_RSA_N, -1, 1 << 32) % (1 << 32)) +
           AVB_RSA_N.to_bytes(256, "big") +
           pow(2, 4096, AVB_RSA_N).to_bytes(256, "big"))
    out = bytearray(payload)
    header = bytearray(out[8192:8448])
    hash_name = "sha256" if algorithm == 1 else "sha512"
    length = hashlib.new(hash_name).digest_size
    struct.pack_into(">I", header, 28, algorithm)
    struct.pack_into(">QQ", header, 40, length, length)
    aux_start = 8448 + 320
    aux_length = struct.unpack_from(">Q", header, 20)[0]
    out[aux_start:aux_start + len(key)] = key
    digest = hashlib.new(hash_name, header + out[aux_start:aux_start + aux_length]).digest()
    out[8192:8448] = header
    out[8448:aux_start] = (digest + AVB_RSA_SIGNATURES[algorithm]).ljust(320, bytes(1))
    return bytes(out), key


def verity_fixture(count=17, algorithm="sha256", block_size=512):
    import hashlib
    salt = b"galwear-test-salt"
    payload = b"".join(bytes([i % 251]) * block_size for i in range(count))
    source = payload
    levels = []
    while len(source) > block_size:
        level = b"".join(hashlib.new(algorithm, salt + source[i:i + block_size]).digest()
                         for i in range(0, len(source), block_size))
        source = level.ljust((len(level) + block_size - 1) // block_size * block_size, bytes(1))
        levels.insert(0, source)
    tree = b"".join(levels)
    root = hashlib.new(algorithm, salt + source).digest()
    return payload, tree, salt, root


def check_verity(payload, tree, salt, root, algorithm="sha256", block_size=512):
    blob = payload + tree
    return audit.r800_apex_inventory.r800_avb_inventory.verify_hashtree(
        lambda offset, length: blob[offset:offset + length],
        len(payload), len(payload), len(tree), block_size, block_size, algorithm, salt, root)


def dex_fixture():
    import hashlib
    import zlib
    raw = bytearray(140)
    raw[:8] = b"dex\n039\0"
    struct.pack_into("<III", raw, 32, len(raw), 112, 0x12345678)
    struct.pack_into("<I", raw, 52, 112)
    struct.pack_into("<II", raw, 104, 28, 112)
    struct.pack_into("<I", raw, 112, 2)
    struct.pack_into("<HHII", raw, 116, 0, 0, 1, 0)
    struct.pack_into("<HHII", raw, 128, 0x1000, 0, 1, 112)
    raw[12:32] = hashlib.sha1(raw[32:]).digest()
    struct.pack_into("<I", raw, 8, zlib.adler32(raw[12:]) & 0xffffffff)
    return bytes(raw)


def jar_fixture(entries):
    import io
    import zipfile
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return out.getvalue()


def oat_elf_fixture(isa="arm64"):
    wide = isa == "arm64"
    data = bytearray(512)
    data[:7] = b"\x7fELF" + bytes((2 if wide else 1, 1, 1))
    struct.pack_into("<HH", data, 16, 3, 183 if wide else 40)
    strings = b"\0.shstrtab\0.rodata\0"
    data[96:96 + len(strings)] = strings
    data[128:136] = b"oat\n183\0"
    if wide:
        struct.pack_into("<Q", data, 40, 256)
        struct.pack_into("<6H", data, 52, 64, 0, 0, 64, 3, 1)
        fmt, step = "<IIQQQQIIQQ", 64
    else:
        struct.pack_into("<I", data, 32, 256)
        struct.pack_into("<6H", data, 40, 52, 0, 0, 40, 3, 1)
        fmt, step = "<10I", 40
    struct.pack_into(fmt, data, 256 + step, 1, 3, 0, 0, 96, len(strings), 0, 0, 1, 0)
    struct.pack_into(fmt, data, 256 + step * 2, 11, 1, 0, 0, 128, 8, 0, 0, 4, 0)
    return bytes(data)


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

    def test_aps2_grouped_arm_and_arm64(self):
        for abi, typ, rela in (("arm", 23, False), ("arm64", 1027, True)):
            with self.subTest(abi=abi):
                blob = aps2_fixture([2, 0x2000, 2, 3, 8, typ])
                out = inspect_aps2(blob, abi, rela)
                self.assertEqual(out["tables"][0]["types"], {str(typ): 2})
                self.assertFalse(out["relocations_applied"])
                self.assertEqual(out["packed_tags"], [])

    def test_aps2_ungrouped_signed_addends(self):
        blob = aps2_fixture([2, 0x2000, 2, 8, 8, 1027, -4, 8, 1027, 6])
        out = inspect_aps2(blob)
        self.assertEqual(out["tables"][0]["count"], 2)

    def test_aps2_grouped_addends(self):
        blob = aps2_fixture([2, 0x2000, 2, 15, 8, 1027, -4])
        self.assertEqual(inspect_aps2(blob)["tables"][0]["count"], 2)

    def test_aps2_invalid_signature_and_truncation(self):
        with self.assertRaisesRegex(ValueError, "signature"):
            inspect_aps2(aps2_fixture([0, 0], signature=b"APS1"))
        with self.assertRaisesRegex(ValueError, "Truncated"):
            inspect_aps2(b"APS2" + bytes([128]))

    def test_aps2_invalid_group_and_flags(self):
        for values in ([1, 0x2000, 2, 0], [1, 0x2000, 1, 16],
                       [1, 0x2000, 1, 4]):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "APS2"):
                inspect_aps2(aps2_fixture(values))

    def test_aps2_rel_rejects_addends(self):
        with self.assertRaisesRegex(ValueError, "addend flags"):
            inspect_aps2(aps2_fixture([1, 0x2000, 1, 8]), "arm", False)

    def test_aps2_checks_symbol_and_target(self):
        with self.assertRaisesRegex(ValueError, "symbol index"):
            inspect_aps2(aps2_fixture([1, 0x2000, 1, 3, 8, (2 << 32) | 1026]))
        with self.assertRaisesRegex(ValueError, "outside PT_LOAD"):
            inspect_aps2(aps2_fixture([1, 0x2000, 1, 3, 256, 1027]))

    def test_aps2_overflow_and_trailing_bytes(self):
        with self.assertRaisesRegex(ValueError, "overflow|too long"):
            inspect_aps2(aps2_fixture([0, 1 << 32]), "arm", False)
        with self.assertRaisesRegex(ValueError, "trailing"):
            inspect_aps2(aps2_fixture([0, 0], trailing=b"x"))

    def test_relr_address_and_bitmap_both_abis(self):
        for abi, typ in (("arm", 23), ("arm64", 1027)):
            with self.subTest(abi=abi):
                table = inspect_relr([0x2000, 0b1011], abi)["tables"][0]
                self.assertEqual(table["count"], 3)
                self.assertEqual(table["encoded_count"], 2)
                self.assertEqual(table["types"], {str(typ): 3})

    def test_android_relr(self):
        out = inspect_relr([0x2000, 3], android=True)
        self.assertEqual(out["tables"][0]["kind"], "ANDROID_RELR")
        self.assertEqual(out["tables"][0]["count"], 2)
        self.assertEqual(out["packed_tags"], [])
        self.assertFalse(out["relocations_applied"])

    def test_relr_consecutive_bitmaps(self):
        out = inspect_relr([0x2000, 3, 3])
        self.assertEqual(out["tables"][0]["count"], 3)

    def test_relr_bitmap_before_address(self):
        with self.assertRaisesRegex(ValueError, "precedes"):
            inspect_relr([3])

    def test_relr_bad_alignment_and_duplicate(self):
        with self.assertRaisesRegex(ValueError, "alignment"):
            inspect_relr([0x2002])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            inspect_relr([0x2000, 0x2000])

    def test_relr_invalid_metadata(self):
        for case in ("size", "entry", "missing", "truncated", "both"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                inspect_relr([0x2000], malformed=case)

    def test_relr_target_outside_memory(self):
        with self.assertRaisesRegex(ValueError, "outside PT_LOAD"):
            inspect_relr([0x3000])

    def test_relr_nonwritable_targets(self):
        out = inspect_relr([0x2000, 3], writable=False)
        self.assertEqual(out["nonwritable_targets"], 2)

    def test_relr_bitmap_cursor_overflow(self):
        data = struct.pack("<II", 0xfffffffc, 3)
        with self.assertRaisesRegex(ValueError, "cursor overflow"):
            audit.relocation_inventory({audit.DT_RELR: [0x1000],
                audit.DT_RELRSZ: [8], audit.DT_RELRENT: [4]}, data,
                [(0x1000, 0, 8)], [(0xfffffffc, 4, 6)], 1, None)

    def test_pt_tls_both_abis(self):
        for abi in ("arm", "arm64"):
            with self.subTest(abi=abi):
                out = audit.inspect(tls_fixture(abi))
                self.assertEqual(out["tls_segment"]["memory_size"], 32)
                self.assertEqual(out["tls_segment"]["file_size"], 8)
                self.assertEqual(out["tls_symbol_count"], 1)
                self.assertNotIn("_tls_indices", out)

    def test_pt_tls_bad_alignment_and_bounds(self):
        for case in ("alignment", "file", "memory", "mapping", "symbol"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                audit.inspect(tls_fixture(malformed=case))

    def test_tlsdesc_both_abis(self):
        for abi, typ in (("arm", 13), ("arm64", 1031)):
            with self.subTest(abi=abi):
                out = inspect_tls_relocation(abi, typ)
                self.assertEqual(out["tls_count"], 1)
                self.assertEqual(out["tlsdesc_count"], 1)
                self.assertTrue(out["tls_symbol_types_checked"])

    def test_tlsdesc_requires_two_words(self):
        for abi, typ, span in (("arm", 13, 4), ("arm64", 1031, 8)):
            with self.subTest(abi=abi), self.assertRaisesRegex(ValueError, "outside PT_LOAD"):
                inspect_tls_relocation(abi, typ, span=span)

    def test_tls_relocation_checks_symbol_kind(self):
        with self.assertRaisesRegex(ValueError, "non-TLS symbol"):
            inspect_tls_relocation("arm64", 1028, tls_indices=set())
        out = inspect_tls_relocation("arm64", 1028, tls_indices=None)
        self.assertFalse(out["tls_symbol_types_checked"])

    def test_tls_relocation_alignment(self):
        with self.assertRaisesRegex(ValueError, "Unaligned TLS"):
            inspect_tls_relocation("arm64", 1031, target=0x2001, span=32)

    def test_tls_relocation_zero_symbol(self):
        out = inspect_tls_relocation("arm64", 1028, sym=0, tls_indices=None)
        self.assertTrue(out["tls_symbol_types_checked"])
        self.assertEqual(out["tls_count"], 1)

    def test_namespace_inventory_arm_and_arm64(self):
        for abi, lib in (("arm", "lib"), ("arm64", "lib64")):
            with self.subTest(abi=abi):
                out = audit.r800_linker_namespaces.parse(NAMESPACE_CONFIG, abi)
                ns = out["sections"]["system"]["default"]
                self.assertEqual(ns["search_paths"], ["/system/" + lib, "/system_ext/" + lib])
                self.assertEqual(ns["links"], ["vendor"])
                self.assertEqual(ns["link_policies"]["vendor"]["shared_libs"], ["libx.so", "liby.so"])
                self.assertEqual(out["unsupported_properties"], [])
                self.assertFalse(out["runtime_resolution_verified"])

    def test_namespace_invalid_links_and_policies(self):
        for config in (
            NAMESPACE_CONFIG.replace("links = vendor", "links = absent"),
            NAMESPACE_CONFIG.replace("links = vendor", "links = default"),
            NAMESPACE_CONFIG.replace("shared_libs = libx.so:liby.so",
                "shared_libs = libx.so\nnamespace.default.link.vendor.allow_all_shared_libs = true"),
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                audit.r800_linker_namespaces.parse(config, "arm64")

    def test_namespace_invalid_paths(self):
        for path in ("/system/../vendor", "relative/lib", "/system/lib::/vendor/lib"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.r800_linker_namespaces.parse("[system]\nnamespace.default.search.paths = " + path, "arm")

    def test_namespace_unknown_properties_and_variables(self):
        cfg = NAMESPACE_CONFIG.replace("/system_ext/${LIB}", "/system_ext/${UNKNOWN}")
        cfg += "namespace.default.asan.search.paths = /data/asan\n"
        out = audit.r800_linker_namespaces.parse(cfg, "arm64")
        self.assertEqual(len(out["unsupported_properties"]), 2)

    def test_namespace_duplicate_property_rejected(self):
        cfg = NAMESPACE_CONFIG + "namespace.default.search.paths = /system/lib\n"
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            audit.r800_linker_namespaces.parse(cfg, "arm64")

    def test_namespace_config_missing_is_not_verified(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["namespace_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["android_namespace_resolution_verified"])

    def test_generated_namespace_config_inventory(self):
        self.put("init", fixture())
        self.put("linkerconfig/ld.config.txt", NAMESPACE_CONFIG.encode())
        out = audit.audit(self.root, ("/init",))
        inventory = out["namespace_inventory"]
        self.assertTrue(inventory["generated_config_present"])
        self.assertEqual(inventory["status"], "CONFIG_INVENTORY_ONLY")
        self.assertFalse(out["android_namespace_resolution_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_malformed_namespace_config_requires_review(self):
        self.put("linkerconfig/ld.config.txt", b"[system]\nnamespace.default.isolated = maybe\n")
        out = audit.r800_linker_namespaces.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertTrue(out["errors"])

    def test_namespace_scope_allowed_vendor_dependency(self):
        self.put("system/bin/service", fixture(needed=["libx.so"]))
        self.put("vendor/lib64/libx.so", fixture())
        self.put("linkerconfig/ld.config.txt", NAMESPACE_CONFIG.encode())
        out = audit.audit(self.root, ("/system/bin/service",))["namespace_scope"]
        self.assertEqual(out["status"], "STATIC_SCOPE_INVENTORY_ONLY")
        self.assertEqual(out["checks"][0]["candidates"][0]["namespace"], "vendor")
        self.assertFalse(out["runtime_resolution_verified"])

    def test_namespace_scope_denied_vendor_dependency(self):
        self.put("system/bin/service", fixture(needed=["libz.so"]))
        self.put("vendor/lib64/libz.so", fixture())
        self.put("linkerconfig/ld.config.txt", NAMESPACE_CONFIG.encode())
        out = audit.audit(self.root, ("/system/bin/service",))["namespace_scope"]
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["checks"][0]["denied_links"], ["vendor"])
        self.assertEqual(out["checks"][0]["candidates"], [])

    def test_namespace_scope_transitive_vendor_dependency(self):
        self.put("system/bin/service", fixture(needed=["libx.so"]))
        self.put("vendor/lib64/libx.so", fixture(needed=["libz.so"]))
        self.put("vendor/lib64/libz.so", fixture())
        self.put("linkerconfig/ld.config.txt", NAMESPACE_CONFIG.encode())
        out = audit.audit(self.root, ("/system/bin/service",))["namespace_scope"]
        self.assertEqual(out["status"], "STATIC_SCOPE_INVENTORY_ONLY")
        self.assertEqual(out["checks"][1]["namespace"], "vendor")

    def test_namespace_scope_custom_path_uninspected(self):
        self.put("system/bin/service", fixture(needed=["libx.so"]))
        self.put("custom/lib64/libx.so", fixture())
        config = NAMESPACE_CONFIG.replace("/vendor/${LIB}", "/custom/${LIB}")
        self.put("linkerconfig/ld.config.txt", config.encode())
        out = audit.audit(self.root, ("/system/bin/service",))["namespace_scope"]
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["checks"][0]["uninspected"], [
            {"namespace": "vendor", "path": "/custom/lib64/libx.so"}])

    def test_namespace_scope_multiple_candidates_require_review(self):
        self.put("system/bin/service", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture())
        self.put("vendor/lib64/libx.so", fixture())
        self.put("linkerconfig/ld.config.txt", NAMESPACE_CONFIG.encode())
        out = audit.audit(self.root, ("/system/bin/service",))["namespace_scope"]
        self.assertEqual(len(out["checks"][0]["candidates"]), 2)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_namespace_section_longest_directory_and_boundary(self):
        ns = audit.r800_linker_namespaces
        cfg = {"directory_sections": {"system": ["/system"], "bin": ["/system/bin"]}}
        self.assertEqual(ns.section_for(cfg, "/system/bin/service"), "bin")
        self.assertIsNone(ns.section_for(cfg, "/systematic/bin/service"))
        cfg["other"] = []
        cfg["directory_sections"]["other"] = ["/system/bin"]
        self.assertIsNone(ns.section_for(cfg, "/system/bin/service"))

    def test_legacy_vndk_llndk_list_inventory(self):
        self.put("system/etc/llndk.libraries.txt", b"# comment\nlibc.so\nlibc.so\nlibm.so\n")
        self.put("system/etc/vndksp.libraries.txt", b"libx.so\n")
        out = audit.r800_linker_namespaces.library_lists(self.root)
        self.assertEqual(out["lists"]["llndk"]["libraries"], ["libc.so", "libm.so"])
        self.assertEqual(out["lists"]["vndk_sp"]["libraries"], ["libx.so"])
        self.assertFalse(out["runtime_policy_verified"])

    def test_legacy_library_list_malformed_entry(self):
        self.put("system/etc/vndkcore.libraries.txt", b"../libx.so\n")
        out = audit.r800_linker_namespaces.library_lists(self.root)
        self.assertTrue(out["errors"])
        self.assertNotIn("vndk_core", out["lists"])

    def put_apex_metadata(self, name, ver=1, manifest_version=None):
        manifest = '{"name":"' + name + '","version":' + str(
            ver if manifest_version is None else manifest_version) + '}'
        self.put("apex/" + name + "/apex_manifest.json", manifest.encode())
        return ('<apex-info moduleName="' + name + '" versionCode="' + str(ver) +
                '" isActive="true" isFactory="true" modulePath="/system/apex/' +
                name + '.apex"/>')

    def test_apex_active_metadata_inventory(self):
        records = [self.put_apex_metadata(name) for name in
                   ("com.android.runtime", "com.android.art", "com.android.vndk.v30")]
        self.put("apex/apex-info-list.xml",
                 ("<apex-info-list>" + "".join(records) + "</apex-info-list>").encode())
        out = audit.r800_apex_inventory.audit(self.root)
        self.assertEqual(out["status"], "METADATA_INVENTORY_ONLY")
        self.assertTrue(out["modules"]["com.android.vndk.v30"]["version_consistent"])
        self.assertFalse(out["apexd_activation_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_apex_duplicate_active_record(self):
        entry = self.put_apex_metadata("com.android.runtime")
        with self.assertRaisesRegex(ValueError, "Duplicate active"):
            audit.r800_apex_inventory.info_list(
                ("<apex-info-list>" + entry * 2 + "</apex-info-list>").encode())

    def test_apex_xml_declaration_rejected(self):
        with self.assertRaisesRegex(ValueError, "declaration"):
            audit.r800_apex_inventory.info_list(b'<!DOCTYPE x><apex-info-list/>')

    def test_apex_version_mismatch(self):
        records = [self.put_apex_metadata("com.android.runtime", 1, 2),
                   self.put_apex_metadata("com.android.art")]
        self.put("apex/apex-info-list.xml",
                 ("<apex-info-list>" + "".join(records) + "</apex-info-list>").encode())
        out = audit.r800_apex_inventory.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["modules"]["com.android.runtime"]["version_consistent"])

    def test_apex_protobuf_presence_not_validation(self):
        self.put("apex/com.android.runtime/apex_manifest.pb", b"x")
        out = audit.r800_apex_inventory.audit(self.root)
        self.assertTrue(out["modules"]["com.android.runtime"]["protobuf_manifest_present"])
        self.assertIsNone(out["modules"]["com.android.runtime"]["json_manifest"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_apex_manifest_invalid_fields(self):
        for raw in (b'{"name":"../lib","version":1}',
                    b'{"name":"com.android.art","version":true}',
                    b'{"name":"com.android.art","version":1,"version":2}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                audit.r800_apex_inventory.json_manifest(raw)

    def test_apex_report_integrated_without_activation_claim(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["apex_metadata"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["apex_activation_verified"])

    def test_apex_protobuf_identity_and_unknown_field(self):
        data = apex_pb() + b"\x2a\x03abc"
        out = audit.r800_apex_inventory.protobuf_manifest(data)
        self.assertEqual(out, {"name": "com.android.runtime", "version": 1})

    def test_apex_protobuf_invalid_identity(self):
        for raw in (apex_pb() + b"\x10\x02", b"\x0a\x80", b"\x10\x01",
                    apex_pb("../x"), apex_pb() + b"\x18" + b"\xff" * 10):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                audit.r800_apex_inventory.protobuf_manifest(raw)

    def test_apex_protobuf_only_expanded_metadata(self):
        records = []
        for name in ("com.android.runtime", "com.android.art"):
            self.put("apex/" + name + "/apex_manifest.pb", apex_pb(name))
            records.append('<apex-info moduleName="' + name +
                           '" versionCode="1" isActive="true" isFactory="true"/>')
        self.put("apex/apex-info-list.xml",
                 ("<apex-info-list>" + "".join(records) + "</apex-info-list>").encode())
        out = audit.r800_apex_inventory.audit(self.root)
        self.assertEqual(out["status"], "METADATA_INVENTORY_ONLY")
        self.assertTrue(out["modules"]["com.android.runtime"]["version_consistent"])

    def test_apex_json_protobuf_mismatch(self):
        self.put_apex_metadata("com.android.runtime", 1)
        self.put("apex/com.android.runtime/apex_manifest.pb", apex_pb(version=2))
        out = audit.r800_apex_inventory.audit(self.root)
        self.assertTrue(any("manifests disagree" in e for e in out["errors"]))

    def test_apex_package_inventory(self):
        path = self.root / "runtime.apex"
        apex_zip(path)
        out = audit.r800_apex_inventory.package_inventory(path)
        self.assertEqual(out["identity"]["name"], "com.android.runtime")
        self.assertEqual(out["payload_offset"], 4096)
        self.assertTrue(out["payload_ext4_magic"])
        self.assertFalse(out["signature_verified"])
        self.assertFalse(out["payload_crc_verified"])

    def test_apex_package_rejects_bad_payload(self):
        path = self.root / "runtime.apex"
        for options in ({"aligned": False}, {"ext4": False}, {"compressed": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                apex_zip(path, **options)
                audit.r800_apex_inventory.package_inventory(path)

    def test_apex_package_bad_manifest(self):
        path = self.root / "runtime.apex"
        apex_zip(path, manifest=b"\x10\x01")
        with self.assertRaises(ValueError):
            audit.r800_apex_inventory.package_inventory(path)

    def test_avb_footer_vbmeta_and_hashtree(self):
        import io
        payload, key = avb_fixture()
        out = audit.r800_apex_inventory.r800_avb_inventory.inspect(io.BytesIO(payload), 0, len(payload), key)
        self.assertEqual(out["status"], "AVB_STRUCTURE_ONLY")
        self.assertTrue(out["vbmeta_digest_matches"])
        self.assertTrue(out["package_key_matches"])
        self.assertEqual(out["descriptors"][0]["tree_bytes"], 4096)
        self.assertFalse(out["signature_verified"])
        self.assertFalse(out["hashtree_verified"])

    def test_avb_digest_or_key_mismatch_requires_review(self):
        import io
        avb = audit.r800_apex_inventory.r800_avb_inventory
        payload, key = avb_fixture("digest")
        out = avb.inspect(io.BytesIO(payload), 0, len(payload), key)
        self.assertFalse(out["vbmeta_digest_matches"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        payload, _ = avb_fixture()
        out = avb.inspect(io.BytesIO(payload), 0, len(payload), b"other")
        self.assertFalse(out["package_key_matches"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_avb_invalid_footer_and_block_bounds(self):
        import io
        for case in ("footer", "block"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                payload, key = avb_fixture(case)
                audit.r800_apex_inventory.r800_avb_inventory.inspect(
                    io.BytesIO(payload), 0, len(payload), key)

    def test_avb_invalid_descriptor_and_geometry(self):
        import io
        for case in ("descriptor", "geometry"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                payload, key = avb_fixture(case)
                audit.r800_apex_inventory.r800_avb_inventory.inspect(
                    io.BytesIO(payload), 0, len(payload), key)

    def test_avb_payload_relative_offset(self):
        import io
        payload, key = avb_fixture()
        out = audit.r800_apex_inventory.r800_avb_inventory.inspect(
            io.BytesIO(b"prefix" + payload + b"suffix"), 6, len(payload), key)
        self.assertTrue(out["footer_present"])
        self.assertEqual(out["vbmeta_offset"], 8192)

    def test_apex_package_without_footer_not_verified(self):
        path = self.root / "unsigned.apex"
        apex_zip(path)
        out = audit.r800_apex_inventory.package_inventory(path)
        self.assertFalse(out["avb"]["footer_present"])
        self.assertEqual(out["avb"]["status"], "REVIEW_REQUIRED")

    def test_avb_rsa_signed_sha256_and_sha512(self):
        import io
        avb = audit.r800_apex_inventory.r800_avb_inventory
        for algorithm in (1, 4):
            with self.subTest(algorithm=algorithm):
                payload, key = signed_avb_fixture(algorithm)
                out = avb.inspect(io.BytesIO(payload), 0, len(payload), key)
                self.assertTrue(out["signature_verified"])
                self.assertFalse(out["trusted_key_verified"])
                self.assertFalse(out["hashtree_verified"])

    def test_avb_rsa_invalid_signature(self):
        import io
        avb = audit.r800_apex_inventory.r800_avb_inventory
        payload, key = signed_avb_fixture()
        damaged = bytearray(payload)
        damaged[8448 + 32] ^= 1
        out = avb.inspect(io.BytesIO(damaged), 0, len(damaged), key)
        self.assertTrue(out["vbmeta_digest_matches"])
        self.assertFalse(out["signature_verified"])

    def test_avb_independent_key_pin(self):
        import io
        import hashlib
        avb = audit.r800_apex_inventory.r800_avb_inventory
        payload, key = signed_avb_fixture()
        pin = hashlib.sha256(key).hexdigest()
        out = avb.inspect(io.BytesIO(payload), 0, len(payload), key, pin)
        self.assertTrue(out["trusted_key_verified"])
        out = avb.inspect(io.BytesIO(payload), 0, len(payload), key, "00" * 32)
        self.assertFalse(out["trusted_key_verified"])
        self.assertTrue(out["signature_verified"])
        out = avb.inspect(io.BytesIO(payload), 0, len(payload), b"wrong", pin)
        self.assertFalse(out["trusted_key_verified"])

    def test_avb_rsa_invalid_montgomery_key(self):
        import hashlib
        avb = audit.r800_apex_inventory.r800_avb_inventory
        payload, key = signed_avb_fixture()
        aux_len = struct.unpack_from(">Q", payload, 8192 + 20)[0]
        digest = hashlib.sha256(payload[8192:8448] + payload[8768:8768 + aux_len]).digest()
        self.assertTrue(avb.rsa_signature_matches(key, AVB_RSA_SIGNATURES[1], digest, "sha256"))
        for index in (4, len(key) - 1):
            damaged = bytearray(key)
            damaged[index] ^= 1
            self.assertFalse(avb.rsa_signature_matches(bytes(damaged), AVB_RSA_SIGNATURES[1], digest, "sha256"))

    def test_avb_invalid_pin_rejected(self):
        import io
        avb = audit.r800_apex_inventory.r800_avb_inventory
        payload, key = signed_avb_fixture()
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            avb.inspect(io.BytesIO(payload), 0, len(payload), key, "not-a-hash")

    def test_verity_single_block_no_tree(self):
        payload, tree, salt, root = verity_fixture(1)
        out = check_verity(payload, tree, salt, root)
        self.assertEqual(out["status"], "HASHTREE_MATCHES_DESCRIPTOR")
        self.assertEqual(out["levels"], 0)
        self.assertEqual(out["data_blocks_checked"], 1)

    def test_verity_multiple_levels_sha256_sha512(self):
        for algorithm in ("sha256", "sha512"):
            with self.subTest(algorithm=algorithm):
                payload, tree, salt, root = verity_fixture(137, algorithm)
                out = check_verity(payload, tree, salt, root, algorithm)
                self.assertEqual(out["status"], "HASHTREE_MATCHES_DESCRIPTOR")
                self.assertEqual(out["data_blocks_checked"], 137)
                self.assertGreater(out["levels"], 1)
                self.assertEqual(out["tree_blocks_checked"], len(tree) // 512)

    def test_verity_changed_payload(self):
        payload, tree, salt, root = verity_fixture()
        changed = bytes([payload[0] ^ 1]) + payload[1:]
        out = check_verity(changed, tree, salt, root)
        self.assertEqual(out["status"], "TREE_BLOCK_MISMATCH")
        self.assertEqual(out["mismatch_level"], 0)

    def test_verity_changed_upper_level(self):
        payload, tree, salt, root = verity_fixture()
        changed = bytes([tree[0] ^ 1]) + tree[1:]
        out = check_verity(payload, changed, salt, root)
        self.assertEqual(out["status"], "TREE_BLOCK_MISMATCH")
        self.assertEqual(out["mismatch_level"], 1)

    def test_verity_tree_padding_checked(self):
        payload, tree, salt, root = verity_fixture()
        changed = tree[:-1] + bytes([1])
        self.assertEqual(check_verity(payload, changed, salt, root)["status"], "TREE_BLOCK_MISMATCH")

    def test_verity_root_and_size_mismatches(self):
        payload, tree, salt, root = verity_fixture()
        self.assertEqual(check_verity(payload, tree, salt, bytes(32))["status"], "ROOT_DIGEST_MISMATCH")
        self.assertEqual(check_verity(payload, tree[:-512], salt, root)["status"], "TREE_SIZE_MISMATCH")

    def test_verity_unsupported_geometry(self):
        payload, tree, salt, root = verity_fixture()
        avb = audit.r800_apex_inventory.r800_avb_inventory
        out = avb.verify_hashtree(lambda o, n: self.fail("Unexpected read"),
            len(payload), len(payload), len(tree), 512, 1024, "sha256", salt, root)
        self.assertEqual(out["status"], "UNSUPPORTED_GEOMETRY")

    def test_avb_tree_mismatch_separate_from_structural_status(self):
        import io
        payload, key = avb_fixture()
        out = audit.r800_apex_inventory.r800_avb_inventory.inspect(
            io.BytesIO(payload), 0, len(payload), key)
        self.assertEqual(out["status"], "AVB_STRUCTURE_ONLY")
        self.assertEqual(out["hashtree_status"], "TREE_SIZE_MISMATCH")
        self.assertFalse(out["hashtree_verified"])
        self.assertFalse(out["payload_authenticated"])

    def test_fec_geometry_absent(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        out = avb.fec_geometry(4096, 4096, 4096, 0, 0, 0, 8192)
        self.assertEqual(out["status"], "NOT_PRESENT")
        self.assertFalse(out["parity_verified"])

    def test_fec_geometry_one_round(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        out = avb.fec_geometry(4096, 4096, 4096, 2, 8192, 8192, 16384)
        self.assertEqual(out["status"], "FEC_GEOMETRY_ONLY")
        self.assertEqual(out["rounds"], 1)
        self.assertEqual(out["data_symbols"], 253)
        self.assertEqual(out["protected_blocks"], 2)
        self.assertFalse(out["recovery_tested"])

    def test_fec_geometry_round_boundary(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        for blocks, rounds in ((253, 1), (254, 2), (506, 2), (507, 3)):
            with self.subTest(blocks=blocks):
                offset = blocks * 4096
                size = rounds * 8192
                out = avb.fec_geometry(4096, 4096, 4096, 2, offset, size, offset + size)
                self.assertEqual(out["expected_bytes"], size)
                self.assertEqual(out["status"], "FEC_GEOMETRY_ONLY")

    def test_fec_geometry_invalid_layout(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        for roots, offset, size, vbmeta in ((2, 4096, 8192, 16384),
                (2, 8193, 8192, 32768), (2, 8192, 8192, 12288),
                (2, 8192, 8191, 32768), (2, 0, 0, 16384)):
            with self.subTest(roots=roots, offset=offset, size=size):
                out = avb.fec_geometry(4096, 4096, 4096, roots, offset, size, vbmeta)
                self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_fec_geometry_wrong_parity_size(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        out = avb.fec_geometry(4096, 4096, 4096, 2, 8192, 4096, 16384)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["expected_bytes"], 8192)

    def test_fec_geometry_root_limits(self):
        avb = audit.r800_apex_inventory.r800_avb_inventory
        for roots in (0, 1, 25, 255):
            with self.subTest(roots=roots):
                out = avb.fec_geometry(4096, 4096, 4096, roots, 8192,
                                       max(1, roots) * 4096, 2 * 1024 * 1024)
                self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_avb_fec_absence_does_not_claim_verification(self):
        import io
        payload, key = avb_fixture()
        out = audit.r800_apex_inventory.r800_avb_inventory.inspect(
            io.BytesIO(payload), 0, len(payload), key)
        self.assertEqual(out["fec_status"], "NOT_PRESENT")
        self.assertFalse(out["fec_verified"])
        self.assertFalse(out["fec_recovery_tested"])

    def test_init_apex_service_and_activation(self):
        self.put("init.rc", b"import /system/etc/init/hw/apex.rc\non early-init\n    start apexd-bootstrap\n")
        self.put("system/etc/init/hw/apex.rc",
                 b"service apexd /system/bin/apexd\n    class core\n    disabled\n"
                 b"on property:apexd.status=ready\n    perform_apex_config\n")
        out = audit.r800_init_inventory.audit(self.root)
        self.assertEqual(out["status"], "STATIC_INIT_INVENTORY_ONLY")
        self.assertEqual(out["services"][0]["name"], "apexd")
        self.assertEqual(len(out["activation_commands"]), 2)
        self.assertFalse(out["apexd_activation_verified"])

    def test_init_art_environment_and_continuation(self):
        self.put("init.rc", b"on init\n    export ANDROID_ART_ROOT /apex/com.android.art\n"
                 b"    export BOOTCLASSPATH \\\n        /apex/com.android.art/javalib/core-oj.jar\n")
        out = audit.r800_init_inventory.audit(self.root)
        self.assertEqual(len(out["art_environment"]), 2)
        self.assertEqual(out["art_environment"][1]["args"][1], "/apex/com.android.art/javalib/core-oj.jar")

    def test_init_property_import_not_expanded(self):
        self.put("init.rc", b"import /init.$" + b"{ro.hardware}.rc\n")
        out = audit.r800_init_inventory.audit(self.root)
        self.assertEqual(len(out["unresolved_imports"]), 1)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_init_duplicate_override_requires_review(self):
        self.put("system/etc/init/a.rc", b"service apexd /system/bin/apexd\n")
        self.put("vendor/etc/init/b.rc", b"service apexd /vendor/bin/apexd\n    override\n")
        out = audit.r800_init_inventory.audit(self.root)
        self.assertEqual(out["duplicate_services"][0]["name"], "apexd")
        self.assertTrue(out["duplicate_services"][0]["override_declared"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_init_import_cycle_bounded(self):
        self.put("init.rc", b"import /other.rc\n")
        self.put("other.rc", b"import /init.rc\nservice apexd /system/bin/apexd\n")
        out = audit.r800_init_inventory.audit(self.root)
        self.assertEqual(len(out["files"]), 2)
        self.assertEqual(out["errors"], [])

    def test_init_malformed_service_and_quoting(self):
        for raw in ("service apexd relative", 'on "broken', "on init\n    start apexd \\"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                audit.r800_init_inventory.parse(raw, "/init.rc")

    def test_init_report_integrated_without_boot_claim(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["init_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["init_inventory"]["init_execution_verified"])
        self.assertFalse(out["android_boot_tested"])

    def test_art_dex_header_integrity(self):
        result = audit.r800_art_inventory.dex_inventory(dex_fixture())
        self.assertEqual(result["version"], "039")
        self.assertTrue(result["checksum_matches"])
        self.assertFalse(result["bytecode_verified"])

    def test_art_dex_corrupt_checksum_and_bounds(self):
        raw = bytearray(dex_fixture())
        raw[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-1"):
            audit.r800_art_inventory.dex_inventory(raw)
        with self.assertRaises(ValueError):
            audit.r800_art_inventory.dex_inventory(raw[:100])

    def test_art_jar_multidex_and_gap(self):
        art = audit.r800_art_inventory
        dex = dex_fixture()
        result, used = art.jar_inventory(jar_fixture({"classes.dex": dex, "classes2.dex": dex}), 1024)
        self.assertEqual(len(result["dex"]), 2)
        self.assertEqual(used, len(dex) * 2)
        with self.assertRaisesRegex(ValueError, "Noncontiguous"):
            art.jar_inventory(jar_fixture({"classes.dex": dex, "classes3.dex": dex}), 1024)

    def test_art_jar_budget_and_missing_dex(self):
        art = audit.r800_art_inventory
        with self.assertRaisesRegex(ValueError, "budget"):
            art.jar_inventory(jar_fixture({"classes.dex": dex_fixture()}), 1)
        result, used = art.jar_inventory(jar_fixture({"META-INF/MANIFEST.MF": b"manifest"}), 1024)
        self.assertEqual(result["status"], "NO_EMBEDDED_DEX")
        self.assertEqual(used, 0)

    def test_art_bootclasspath_inventory(self):
        self.put("init.rc", b"on init\n    export BOOTCLASSPATH /system/framework/core.jar\n")
        self.put("system/framework/core.jar", jar_fixture({"classes.dex": dex_fixture()}))
        out = audit.r800_art_inventory.audit(self.root, audit.r800_init_inventory.audit(self.root))
        self.assertEqual(out["status"], "STATIC_DEX_INVENTORY_ONLY")
        self.assertFalse(out["art_initialization_verified"])

    def test_art_classpath_missing_and_unresolved(self):
        self.put("init.rc", b"on init\n    export BOOTCLASSPATH /missing.jar:/$" + b"{ART}/core.jar\n")
        out = audit.r800_art_inventory.audit(self.root, audit.r800_init_inventory.audit(self.root))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(out["errors"]), 2)

    def test_art_report_integrated_without_runtime_claim(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["art_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["art_inventory"]["oat_verified"])
        self.assertFalse(out["android_boot_tested"])

    def test_art_precompiled_boot_group(self):
        for suffix, head in (("art", b"art\n085\0"), ("oat", b"oat\n183\0"), ("vdex", b"vdex021\0")):
            self.put("system/framework/arm/boot." + suffix, head)
        out = audit.r800_art_precompiled.audit(self.root)
        self.assertEqual(out["status"], "PRECOMPILED_HEADER_INVENTORY_ONLY")
        self.assertTrue(out["groups"]["/system/framework/arm/boot"]["companion_headers_present"])
        self.assertFalse(out["boot_image_verified"])

    def test_art_precompiled_missing_companion(self):
        self.put("system/framework/arm/boot.art", b"art\n085\0")
        out = audit.r800_art_precompiled.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["groups"]["/system/framework/arm/boot"]["companion_headers_present"])

    def test_art_precompiled_elf_oat_both_isas(self):
        for isa in ("arm", "arm64"):
            with self.subTest(isa=isa):
                path = "system/framework/" + isa + "/boot.oat"
                self.put(path, oat_elf_fixture(isa))
                info = audit.r800_art_precompiled.inspect(self.root / path, ".oat", isa)
                self.assertEqual(info["version"], "183")
                self.assertTrue(info["elf_wrapped"])
                self.assertTrue(info["isa_verified"])
                self.assertFalse(info["compatibility_verified"])

    def test_art_precompiled_wrong_isa(self):
        path = "system/framework/arm/boot.oat"
        self.put(path, oat_elf_fixture("arm64"))
        with self.assertRaisesRegex(ValueError, "ISA"):
            audit.r800_art_precompiled.inspect(self.root / path, ".oat", "arm")

    def test_art_precompiled_bad_elf_bounds(self):
        path = "system/framework/arm64/boot.oat"
        raw = bytearray(oat_elf_fixture())
        struct.pack_into("<Q", raw, 40, 99999)
        self.put(path, raw)
        with self.assertRaisesRegex(ValueError, "bounds"):
            audit.r800_art_precompiled.inspect(self.root / path, ".oat", "arm64")

    def test_art_precompiled_invalid_magic(self):
        self.put("system/framework/arm/boot.vdex", b"vdexabc\0")
        out = audit.r800_art_precompiled.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertTrue(out["errors"])

    def test_art_precompiled_report_integrated(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["art_precompiled"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["art_precompiled"]["dex2oat_executed"])
        self.assertFalse(out["safe_to_flash"])

    def put_art_executable(self, path, abi="arm"):
        raw = fixture(abi)
        # Preflight checks executable entry and filesystem execute permission.
        struct.pack_into("<Q" if abi == "arm64" else "<I", raw, 24, 0x1000)
        self.put(path, raw)
        (self.root / path.lstrip("/")).chmod(0o755)

    def art_launch_fixture(self, mode="zygote32", abi="arm"):
        self.put("system/build.prop", ("ro.zygote=" + mode + "\n").encode())
        self.put("init.rc", b"service zygote /system/bin/app_process32 -Xzygote /system/bin --zygote --start-system-server\n")
        self.put_art_executable("system/bin/app_process32", abi)
        self.put_art_executable("system/bin/dex2oat32")
        for suffix, head in (("art", b"art\n085\0"), ("oat", b"oat\n183\0"), ("vdex", b"vdex021\0")):
            self.put("system/framework/arm/boot." + suffix, head)

    def inspect_art_launch(self):
        return audit.r800_art_launch.audit(self.root, audit.r800_init_inventory.audit(self.root),
                                           audit.r800_art_precompiled.audit(self.root))

    def test_art_launch_zygote32_static_prerequisites(self):
        self.art_launch_fixture()
        out = self.inspect_art_launch()
        self.assertEqual(out["status"], "STATIC_LAUNCH_INVENTORY_ONLY")
        self.assertEqual(out["expected_abis"], ["arm"])
        self.assertFalse(out["zygote_started"])
        self.assertFalse(out["dex2oat_executed"])

    def test_art_launch_zygote_abi_mismatch(self):
        self.art_launch_fixture(abi="arm64")
        out = self.inspect_art_launch()
        self.assertTrue(any("ro.zygote ABI mismatch" in e for e in out["errors"]))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_art_launch_dual_mode_missing_secondary(self):
        self.art_launch_fixture(mode="zygote32_64")
        out = self.inspect_art_launch()
        self.assertIn("Missing inspected service: zygote_secondary", out["errors"])
        self.assertEqual(out["missing_boot_image_candidates"], ["arm64"])

    def test_art_launch_conflicting_properties(self):
        self.art_launch_fixture()
        self.put("vendor/build.prop", b"ro.zygote=zygote64\n")
        out = self.inspect_art_launch()
        self.assertIsNone(out["zygote_mode"])
        self.assertFalse(out["property_precedence_verified"])

    def test_art_launch_compiler_abi_mismatch(self):
        self.art_launch_fixture()
        self.put_art_executable("system/bin/dex2oat32", "arm64")
        out = self.inspect_art_launch()
        self.assertIsNone(out["dex2oat"]["/system/bin/dex2oat32"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_art_launch_missing_zygote_arguments(self):
        self.art_launch_fixture()
        self.put("init.rc", b"service zygote /system/bin/app_process32\n")
        out = self.inspect_art_launch()
        self.assertIn("zygote: --zygote missing", out["errors"])
        self.assertIn("zygote: system-server argument missing", out["errors"])

    def test_art_launch_report_integrated(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["art_launch"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["art_launch"]["system_server_started"])
        self.assertFalse(out["safe_to_flash"])

    def binder_fixture(self):
        self.art_launch_fixture()
        rc = b"service zygote /system/bin/app_process32 --zygote --start-system-server\n"
        for name, path in audit.r800_binder_inventory.SERVICES.items():
            rc += ("service " + name + " " + path + "\n    class core\n").encode()
            self.put_art_executable(path)
        rc += b"on init\n    start servicemanager\n    export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n"
        self.put("init.rc", rc)
        self.put("system/framework/services.jar", jar_fixture({"classes.dex": dex_fixture()}))
        self.put("ueventd.rc", b"/dev/binder 0666 root root\n/dev/hwbinder 0666 root root\n")
        return {"CONFIG_ANDROID_BINDER_IPC": "y", "CONFIG_COMPAT": "y",
                "CONFIG_ANDROID_BINDER_DEVICES": '"binder,hwbinder,vndbinder"'}

    def inspect_binder(self, kernel=None):
        init = audit.r800_init_inventory.audit(self.root)
        art = audit.r800_art_inventory.audit(self.root, init)
        launch = audit.r800_art_launch.audit(self.root, init, audit.r800_art_precompiled.audit(self.root))
        return audit.r800_binder_inventory.audit(self.root, init, art, launch, kernel)

    def test_binder_static_manager_inventory(self):
        config = self.binder_fixture()
        out = self.inspect_binder(config)
        self.assertEqual(out["status"], "STATIC_BINDER_INVENTORY_ONLY")
        self.assertEqual(len(out["managers"]), 3)
        self.assertEqual(len(out["ueventd_rules"]), 2)
        self.assertEqual(out["init_commands"][0]["args"], ["servicemanager"])
        self.assertFalse(out["binder_transaction_verified"])

    def test_binder_missing_kernel_evidence(self):
        self.binder_fixture()
        out = self.inspect_binder()
        self.assertEqual(out["kernel"]["status"], "NOT_PROVIDED")
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_binder_incomplete_kernel_config(self):
        config = self.binder_fixture()
        config["CONFIG_ANDROID_BINDER_DEVICES"] = '"binder"'
        out = self.inspect_binder(config)
        self.assertIn("CONFIG_ANDROID_BINDER_DEVICES", out["kernel"]["missing"])

    def test_binder_regular_file_is_not_device(self):
        config = self.binder_fixture()
        self.put("dev/binder", b"fake")
        out = self.inspect_binder(config)
        self.assertFalse(out["device_nodes"]["binder"]["character_device_present"])
        self.assertTrue(any("not a character device" in e for e in out["errors"]))

    def test_binder_unresolved_ueventd_import(self):
        config = self.binder_fixture()
        self.put("ueventd.rc", b"import /vendor/ueventd.rc\n/dev/binder 9999 root root\n")
        out = self.inspect_binder(config)
        self.assertEqual(len(out["unresolved_ueventd_imports"]), 1)
        self.assertTrue(any("malformed Binder permission" in e for e in out["errors"]))

    def test_binder_systemserver_missing_jar(self):
        config = self.binder_fixture()
        (self.root / "system/framework/services.jar").unlink()
        out = self.inspect_binder(config)
        self.assertEqual(out["system_server"]["missing_or_unverified"], ["/system/framework/services.jar"])
        self.assertFalse(out["system_server_started"])

    def test_binder_report_integrated(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["binder_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["binder_inventory"]["service_registration_verified"])
        self.assertFalse(out["safe_to_flash"])

    def vintf_fixture(self, optional=False, instance="default"):
        self.put("vendor/etc/vintf/manifest.xml", b'<manifest type="device" version="1.0" target-level="5"><hal format="hidl"><name>android.hardware.graphics.composer</name><transport>hwbinder</transport><fqname>@2.2::IComposer/default</fqname></hal></manifest>')
        matrix = ('<compatibility-matrix type="framework" version="1.0" level="5"><hal format="hidl" optional="' +
                  ("true" if optional else "false") + '"><name>android.hardware.graphics.composer</name><version>2.1-3</version><interface><name>IComposer</name><instance>' +
                  instance + '</instance></interface></hal></compatibility-matrix>')
        self.put("system/etc/vintf/compatibility_matrix.5.xml", matrix.encode())

    def test_vintf_literal_hidl_range(self):
        self.vintf_fixture()
        out = audit.r800_vintf_inventory.audit(self.root)
        self.assertEqual(out["status"], "LITERAL_INVENTORY_ONLY")
        self.assertEqual(out["comparisons"][0]["status"], "LITERAL_MATCH")
        self.assertFalse(out["vintf_compatibility_verified"])

    def test_vintf_missing_required_instance(self):
        self.vintf_fixture(instance="missing")
        out = audit.r800_vintf_inventory.audit(self.root)
        self.assertEqual(out["comparisons"][0]["status"], "NO_LITERAL_MATCH")
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_vintf_missing_optional_instance(self):
        self.vintf_fixture(optional=True, instance="missing")
        out = audit.r800_vintf_inventory.audit(self.root)
        self.assertEqual(out["comparisons"][0]["status"], "OPTIONAL_NOT_FOUND")

    def test_vintf_aidl_fqname(self):
        raw = b'<manifest type="device"><hal format="aidl"><name>android.hardware.vibrator</name><version>2</version><fqname>IVibrator/default</fqname></hal></manifest>'
        doc = audit.r800_vintf_inventory.parse(raw, "fixture")
        self.assertEqual(doc["entries"][0]["version"], [0, 2, 2])
        self.assertEqual(doc["entries"][0]["interface"], "IVibrator")

    def test_vintf_regex_and_override_require_review(self):
        raw = b'<manifest type="device"><hal override="true"><name>android.hardware.foo</name><version>1.0</version><interface><name>IFoo</name><regex-instance>.*</regex-instance></interface></hal></manifest>'
        doc = audit.r800_vintf_inventory.parse(raw, "fixture")
        self.assertEqual(len(doc["review"]), 2)
        self.assertEqual(doc["entries"], [])

    def test_vintf_invalid_xml_and_ranges(self):
        vintf = audit.r800_vintf_inventory
        with self.assertRaises(ValueError):
            vintf.parse(b'<!DOCTYPE x><manifest type="device"/>', "fixture")
        with self.assertRaises(ValueError):
            vintf.version_range("2.3-1", "hidl")

    def test_vintf_report_integrated(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["vintf_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["vintf_inventory"]["hal_registration_verified"])
        self.assertFalse(out["safe_to_flash"])

    def graphics_fixture(self):
        self.put("init.rc", b"service surfaceflinger /system/bin/surfaceflinger\n"
                 b"service vendor.composer /vendor/bin/hw/composer\n"
                 b"    interface android.hardware.graphics.composer@2.1::IComposer default\n")
        self.put_art_executable("system/bin/surfaceflinger", "arm")
        self.put_art_executable("vendor/bin/hw/composer", "arm")
        hals = "".join('<hal format="hidl"><name>android.hardware.graphics.' + name +
                       '</name><fqname>@2.1::I' + name.capitalize() +
                       '/default</fqname></hal>' for name in ("composer", "allocator", "mapper"))
        self.put("vendor/etc/vintf/manifest.xml", ('<manifest type="device">' + hals + '</manifest>').encode())
        for name in ("libEGL_mali.so", "libGLESv2_mali.so", "libMali.so"):
            self.put("vendor/lib/egl/" + name, fixture("arm"))

    def inspect_graphics(self, kernel=None):
        return audit.r800_graphics_inventory.audit(
            self.root, audit.r800_init_inventory.audit(self.root),
            audit.r800_vintf_inventory.audit(self.root), audit.inspect, kernel)

    def test_graphics_surfaceflinger_hal_and_egl_candidates(self):
        self.graphics_fixture()
        out = self.inspect_graphics({"CONFIG_DRM": "y"})
        self.assertEqual(out["status"], "STATIC_GRAPHICS_INVENTORY_ONLY")
        self.assertEqual(out["surfaceflinger_abi"], "arm")
        self.assertEqual(len(out["services"]), 2)
        self.assertEqual(len(out["candidates"]["arm"]["mali"]), 1)
        self.assertEqual(out["kernel_config"]["CONFIG_DRM"], "y")
        self.assertFalse(out["egl_initialized"])
        self.assertFalse(out["gpu_driver_compatible"])

    def test_graphics_wrong_library_abi(self):
        self.graphics_fixture()
        self.put("vendor/lib/egl/libEGL_mali.so", fixture("arm64"))
        out = self.inspect_graphics()
        self.assertIsNone(out["libraries"]["/vendor/lib/egl/libEGL_mali.so"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_graphics_missing_hal(self):
        self.graphics_fixture()
        self.put("vendor/etc/vintf/manifest.xml", b'<manifest type="device"/>')
        out = self.inspect_graphics()
        self.assertEqual(out["missing_hal_declarations"], ["composer", "allocator", "mapper"])

    def test_graphics_missing_surfaceflinger(self):
        self.graphics_fixture()
        (self.root / "system/bin/surfaceflinger").unlink()
        out = self.inspect_graphics()
        self.assertIsNone(out["surfaceflinger_abi"])
        self.assertEqual(out["status"], "REVIEW_REQUIRED")

    def test_graphics_fake_device_node(self):
        self.graphics_fixture()
        self.put("dev/mali0", b"not device")
        out = self.inspect_graphics()
        self.assertFalse(out["device_nodes"]["/dev/mali0"])
        self.assertTrue(any("not a character device" in e for e in out["errors"]))

    def test_graphics_legacy_hal_inventory(self):
        self.graphics_fixture()
        self.put("vendor/lib/hw/gralloc.exynos.so", fixture("arm"))
        out = self.inspect_graphics()
        self.assertIn("/vendor/lib/hw/gralloc.exynos.so", out["candidates"]["arm"]["legacy_hal"])
        self.assertFalse(out["hal_registration_verified"])

    def test_graphics_report_integrated(self):
        self.put("init", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["graphics_inventory"]["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["graphics_inventory"]["display_output_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_symlink_alias_not_ambiguous(self):
        self.put("init", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture())
        p = self.root / "vendor/lib64/libx.so"
        p.parent.mkdir(parents=True)
        p.symlink_to("/system/lib64/libx.so")
        self.assertEqual(audit.audit(self.root, ("/init",))["status"], "CANDIDATES_FOUND_ONLY")


if __name__ == "__main__":
    unittest.main()
