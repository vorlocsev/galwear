#!/usr/bin/env python3
"""Bounded read-only AVB footer/VBMeta inspection; no trust or signature claims."""
from __future__ import annotations
import hashlib
import hmac
import struct

MAX_VBMETA = 1024 * 1024


def inspect(stream, base, size, package_key):
    def read(off, length):
        if off < 0 or length < 0 or off + length > size or length > MAX_VBMETA:
            raise ValueError("AVB read outside payload")
        stream.seek(base + off)
        data = stream.read(length)
        if len(data) != length:
            raise ValueError("Truncated AVB data")
        return data

    result = {"status": "REVIEW_REQUIRED", "footer_present": False,
              "signature_verified": False, "trusted_key_verified": False,
              "hashtree_verified": False, "rollback_verified": False}
    if size < 64:
        raise ValueError("AVB payload too small")
    footer = read(size - 64, 64)
    if footer[:4] != b"AVBf":
        return result
    major, minor, original, offset, length = struct.unpack_from(">IIQQQ", footer, 4)
    if (major != 1 or minor != 0 or any(footer[36:]) or
            not 0 < original <= offset or not 256 <= length <= MAX_VBMETA or
            offset + length > size - 64):
        raise ValueError("Invalid AVB footer bounds or version")
    blob = read(offset, length)
    if blob[:4] != b"AVB0":
        raise ValueError("Invalid VBMeta magic")
    libmajor, libminor, auth_size, aux_size, algorithm = struct.unpack_from(">IIQQI", blob, 4)
    if (libmajor != 1 or auth_size % 64 or aux_size % 64 or
            256 + auth_size + aux_size != length or any(blob[176:256])):
        raise ValueError("Invalid VBMeta header or block size")
    auth = blob[256:256 + auth_size]
    aux = blob[256 + auth_size:]
    fields = struct.unpack_from(">11QII", blob, 32)
    ho, hs, so, ss, ko, ks, mo, ms, do, ds, rollback, flags, location = fields

    def slices(block, regions):
        spans = []
        for off, n in regions:
            if off > len(block) or n > len(block) - off:
                raise ValueError("VBMeta field outside block")
            if n:
                spans.append((off, off + n))
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise ValueError("Overlapping VBMeta fields")
        return [block[o:o+n] for o, n in regions]

    digest, signature = slices(auth, ((ho, hs), (so, ss)))
    key, _, descriptors = slices(aux, ((ko, ks), (mo, ms), (do, ds)))
    algorithms = {1: ("sha256", 256), 2: ("sha256", 512), 3: ("sha256", 1024),
                  4: ("sha512", 256), 5: ("sha512", 512), 6: ("sha512", 1024)}
    issues = []
    hash_matches = None
    key_matches = None
    if algorithm in algorithms:
        hash_name, rsa_bytes = algorithms[algorithm]
        calculated = hashlib.new(hash_name, blob[:256] + aux).digest()
        if hs != len(calculated) or ss != rsa_bytes or ks != 8 + 2 * rsa_bytes:
            raise ValueError("Invalid VBMeta authentication sizes")
        if struct.unpack_from(">I", key)[0] != rsa_bytes * 8:
            raise ValueError("Invalid VBMeta RSA key size")
        hash_matches = hmac.compare_digest(digest, calculated)
        key_matches = hmac.compare_digest(key, package_key)
        if not hash_matches:
            issues.append("VBMeta digest mismatch")
        if not key_matches:
            issues.append("Embedded AVB key differs from package key")
    else:
        issues.append("Unsigned or unsupported VBMeta algorithm")
    if flags:
        issues.append("Nonzero VBMeta flags")
    if location:
        issues.append("Nonzero rollback index location")

    items = []
    pos = 0
    while pos < len(descriptors):
        if len(items) >= 256 or len(descriptors) - pos < 16:
            raise ValueError("Invalid VBMeta descriptor count or header")
        tag, following = struct.unpack_from(">QQ", descriptors, pos)
        if following % 8 or following > len(descriptors) - pos - 16:
            raise ValueError("Invalid VBMeta descriptor length")
        body = descriptors[pos + 16:pos + 16 + following]
        pos += 16 + following
        item = {"tag": tag, "bytes": following}
        if tag == 1:
            if len(body) < 164:
                raise ValueError("Truncated AVB hashtree descriptor")
            dm, image, tree, tree_size, db, hb, roots, fec, fec_size = struct.unpack_from(">IQQQIIIQQ", body)
            hash_alg = body[56:88].split(b"\0", 1)[0].decode("ascii")
            pn, salt, digest_len, desc_flags = struct.unpack_from(">IIII", body, 88)
            end = 164 + pn + salt + digest_len
            if end > len(body) or any(body[104:164]) or any(body[end:]) or len(body) - end >= 8:
                raise ValueError("Invalid AVB hashtree variable fields")
            if (dm != 1 or not 512 <= db <= 65536 or db & (db-1) or
                    not 512 <= hb <= 65536 or hb & (hb-1) or
                    not original <= image <= tree <= offset or
                    image % db or tree % hb or tree_size % hb or tree_size > offset - tree):
                raise ValueError("Invalid AVB hashtree geometry")
            if fec_size and (not roots or fec < tree + tree_size or fec + fec_size > offset):
                raise ValueError("Invalid AVB FEC geometry")
            if not fec_size and roots:
                issues.append("FEC roots without FEC data")
            if hash_alg not in ("sha256", "sha512") or digest_len != {"sha256": 32, "sha512": 64}.get(hash_alg):
                issues.append("Unsupported or persistent hashtree digest")
            partition = body[164:164+pn].decode("utf-8")
            item.update({"partition": partition, "image_bytes": image,
                         "tree_offset": tree, "tree_bytes": tree_size,
                         "data_block": db, "hash_block": hb, "hash_algorithm": hash_alg,
                         "fec_offset": fec, "fec_bytes": fec_size, "flags": desc_flags})
        else:
            issues.append("Descriptor tag not semantically inspected: " + str(tag))
        items.append(item)
    if sum(i["tag"] == 1 for i in items) != 1:
        issues.append("Expected one APEX hashtree descriptor")
    result.update({"status": "AVB_STRUCTURE_ONLY" if not issues else "REVIEW_REQUIRED",
                   "footer_present": True, "original_bytes": original,
                   "vbmeta_offset": offset, "vbmeta_bytes": length,
                   "required_libavb": [libmajor, libminor], "algorithm": algorithm,
                   "rollback_index": rollback, "flags": flags, "descriptors": items,
                   "vbmeta_digest_matches": hash_matches, "package_key_matches": key_matches,
                   "issues": issues})
    return result
