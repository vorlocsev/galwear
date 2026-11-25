#!/usr/bin/env python3
"""Read-only AVB inventory and embedded-key RSA checks; no platform trust claims."""
from __future__ import annotations
import hashlib
import hmac
import struct

MAX_VBMETA = 1024 * 1024


DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rsa_signature_matches(key, signature, digest, hash_name):
    """Verify AVB RSA public key encoding and exact PKCS#1 v1.5 digest block."""
    if hash_name not in DIGEST_INFO or len(digest) != hashlib.new(hash_name).digest_size:
        return False
    width = len(signature)
    if width not in (256, 512, 1024) or len(key) != 8 + 2 * width:
        return False
    bits, n0inv = struct.unpack_from(">II", key)
    n = int.from_bytes(key[8:8 + width], "big")
    rr = int.from_bytes(key[8 + width:], "big")
    if bits != width * 8 or n.bit_length() != bits or not n & 1:
        return False
    if (n * n0inv + 1) % (1 << 32) or rr != pow(2, 2 * bits, n):
        return False
    s = int.from_bytes(signature, "big")
    if not 0 < s < n:
        return False
    encoded = pow(s, 65537, n).to_bytes(width, "big")
    suffix = DIGEST_INFO[hash_name] + digest
    pad = width - len(suffix) - 3
    if pad < 8:
        return False
    expected = bytes((0, 1)) + bytes((255,)) * pad + bytes((0,)) + suffix
    return hmac.compare_digest(encoded, expected)


MAX_HASHED_BYTES = 2 * 1024 * 1024 * 1024


def verify_hashtree(read, image, tree, tree_size, db, hb, algorithm, salt, root):
    """Compare AVB v1 tree bottom-up, using verified stored blocks for upper levels."""
    out = {"status": "REVIEW_REQUIRED", "levels": 0, "data_blocks_checked": 0,
           "tree_blocks_checked": 0, "root_matches": False}
    if (algorithm not in ("sha256", "sha512") or
            len(root) != hashlib.new(algorithm).digest_size or db != hb or
            not 512 <= db <= 65536 or db & (db - 1) or
            image <= 0 or image % db or tree < image or tree % hb or
            tree_size < 0 or image + tree_size > MAX_HASHED_BYTES):
        out["status"] = "UNSUPPORTED_GEOMETRY"
        return out
    digest_size = len(root)
    fanout = hb // digest_size
    sizes = []
    blocks = image // db
    while blocks > 1:
        blocks = (blocks + fanout - 1) // fanout
        sizes.append(blocks * hb)
    out["levels"] = len(sizes)
    out["expected_tree_bytes"] = sum(sizes)
    if sum(sizes) != tree_size:
        out["status"] = "TREE_SIZE_MISMATCH"
        return out

    def salted(block):
        h = hashlib.new(algorithm, salt)
        h.update(block)
        return h.digest()

    src, count = 0, image // db
    for level, length in enumerate(sizes):
        dest = tree + sum(sizes[level + 1:])
        for group in range(length // hb):
            # Bound memory to one hash block plus one input block.
            expected = bytearray(hb)
            start = group * fanout
            stop = min(start + fanout, count)
            for index in range(start, stop):
                digest = salted(read(src + index * db, db))
                slot = (index - start) * digest_size
                expected[slot:slot + digest_size] = digest
                if level == 0:
                    out["data_blocks_checked"] += 1
            actual = read(dest + group * hb, hb)
            if not hmac.compare_digest(expected, actual):
                out["status"] = "TREE_BLOCK_MISMATCH"
                out["mismatch_level"] = level
                out["mismatch_block"] = group
                return out
            out["tree_blocks_checked"] += 1
        src, count = dest, length // hb
    if not sizes:
        out["data_blocks_checked"] = 1
    out["root_matches"] = hmac.compare_digest(salted(read(src, db)), root)
    out["status"] = "HASHTREE_MATCHES_DESCRIPTOR" if out["root_matches"] else "ROOT_DIGEST_MISMATCH"
    return out


def inspect(stream, base, size, package_key, trusted_key_sha256=None):
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
    if trusted_key_sha256 is not None:
        if (not isinstance(trusted_key_sha256, str) or len(trusted_key_sha256) != 64 or
                any(ch not in "0123456789abcdefABCDEF" for ch in trusted_key_sha256)):
            raise ValueError("Invalid independently supplied trusted key fingerprint")
        trusted_key_sha256 = trusted_key_sha256.lower()
    result["signature_status"] = "NOT_CHECKED"
    result["hashtree_status"] = "NOT_CHECKED"
    result["fec_verified"] = False
    result["key_fingerprint_matches"] = None
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
        rsa_ok = rsa_signature_matches(key, signature, calculated, hash_name)
        result["signature_verified"] = bool(rsa_ok and hash_matches)
        result["signature_status"] = ("EMBEDDED_KEY_SIGNATURE_VALID" if result["signature_verified"]
                                      else "INVALID_SIGNATURE_OR_KEY")
        result["embedded_key_sha256"] = hashlib.sha256(key).hexdigest()
        if trusted_key_sha256 is not None:
            result["key_fingerprint_matches"] = hmac.compare_digest(
                result["embedded_key_sha256"], trusted_key_sha256)
            result["trusted_key_verified"] = bool(result["key_fingerprint_matches"] and
                                                  result["signature_verified"] and key_matches)
    else:
        result["signature_status"] = "UNSUPPORTED_OR_UNSIGNED"
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
            salt_bytes = body[164+pn:164+pn+salt]
            root_digest = body[164+pn+salt:end]
            if any(i["tag"] == 1 for i in items):
                raise ValueError("Duplicate APEX hashtree descriptor")
            tree_check = verify_hashtree(read, image, tree, tree_size, db, hb,
                                         hash_alg, salt_bytes, root_digest)
            item["hashtree_check"] = tree_check
            item.update({"partition": partition, "image_bytes": image,
                         "tree_offset": tree, "tree_bytes": tree_size,
                         "data_block": db, "hash_block": hb, "hash_algorithm": hash_alg,
                         "fec_offset": fec, "fec_bytes": fec_size, "flags": desc_flags})
        else:
            issues.append("Descriptor tag not semantically inspected: " + str(tag))
        items.append(item)
    trees = [i["hashtree_check"] for i in items if i["tag"] == 1]
    if len(trees) != 1:
        issues.append("Expected one APEX hashtree descriptor")
    else:
        result["hashtree_status"] = trees[0]["status"]
        result["hashtree_verified"] = trees[0]["status"] == "HASHTREE_MATCHES_DESCRIPTOR"
    # Keep structural status separate from cryptographic and payload evidence.
    result["payload_authenticated"] = bool(result["hashtree_verified"] and
                                            result["trusted_key_verified"] and not issues)
    result.update({"status": "AVB_STRUCTURE_ONLY" if not issues else "REVIEW_REQUIRED",
                   "footer_present": True, "original_bytes": original,
                   "vbmeta_offset": offset, "vbmeta_bytes": length,
                   "required_libavb": [libmajor, libminor], "algorithm": algorithm,
                   "rollback_index": rollback, "flags": flags, "descriptors": items,
                   "vbmeta_digest_matches": hash_matches, "package_key_matches": key_matches,
                   "issues": issues})
    return result
