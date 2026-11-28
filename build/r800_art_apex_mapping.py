#!/usr/bin/env python3
"""Explicit packaged APEX mappings for offline ART classpath inspection."""
import hashlib
from pathlib import Path
import re
import shutil

from r800_apex_inventory import module_name, package_inventory, protobuf_manifest, json_manifest, MAX_METADATA
from r800_android_runtime_extract import extract_payload, MAX_APEX, MAX_PAYLOAD
from r800_framework_inventory import ext4_member
from r800_partition_identity import filesystem
from r800_donor_preflight import digest
from r800_extract_super import require

MAX_PACKAGES = 8
MAX_AGGREGATE = 512*1024**2
PACKAGE_PATH = re.compile(r"/(?:system|system_ext|product|vendor|odm)/apex/[A-Za-z0-9_.@-]+\.apex")


def mappings(specs):
    require(len(specs) <= MAX_PACKAGES, "APEX package count exceeded")
    rows, paths = {}, set()
    for module, path, pin in specs:
        module_name(module)
        require(PACKAGE_PATH.fullmatch(path) and re.fullmatch(r"[0-9a-f]{64}", pin),
                "Invalid APEX path or SHA-256")
        require(module not in rows and path not in paths, "Duplicate APEX mapping")
        rows[module] = (path, pin)
        paths.add(path)
    return rows


class ApexReader:
    def __init__(self, specs, read_partition, scratch):
        self.specs = mappings(specs)
        self.read_partition = read_partition
        self.scratch = scratch
        self.cache = {}
        self.total = 0
        self.evidence = {}

    def open(self, module):
        if module in self.cache:
            return self.cache[module]
        path, pin = self.specs[module]
        tool = shutil.which("debugfs")
        require(tool, "debugfs required for APEX payload")
        raw = self.read_partition(path, min(MAX_APEX, MAX_AGGREGATE-self.total))
        require(raw is not None and hashlib.sha256(raw).hexdigest() == pin,
                "APEX package missing or SHA-256 mismatch")
        self.total += len(raw)
        directory = self.scratch / ("apex-"+str(len(self.cache)))
        directory.mkdir()
        package, payload = directory/"package.apex", directory/"payload.img"
        package.write_bytes(raw)
        del raw
        info = package_inventory(package)
        require(info["identity"]["name"] == module, "APEX package module mismatch")
        require(0 < info["payload_bytes"] <= min(MAX_PAYLOAD, MAX_AGGREGATE-self.total),
                "APEX aggregate payload budget exceeded")
        extract_payload(package, payload)
        payload.chmod(0o400)
        payload_info = digest(payload, MAX_PAYLOAD)
        require(payload_info["bytes"] == info["payload_bytes"], "APEX payload length mismatch")
        self.total += payload_info["bytes"]
        require(filesystem(payload)["kind"] == "EXT4", "APEX payload is not EXT4")
        inner = {}
        for filename, parser in (("apex_manifest.pb", protobuf_manifest),
                                 ("apex_manifest.json", json_manifest)):
            content = ext4_member(tool, payload, "/"+filename, MAX_METADATA, directory)
            if content is not None:
                require(parser(content) == info["identity"], "APEX inner manifest mismatch")
                inner[filename] = hashlib.sha256(content).hexdigest()
        require(inner, "APEX inner manifest missing")
        evidence = {"package_path": path, "package_sha256": pin,
                    "payload_sha256": payload_info["sha256"], "identity": info["identity"],
                    "inner_manifests": inner, "avb_observation": info["avb"],
                    "package_authenticity_verified": False, "activation_verified": False}
        self.evidence[module] = evidence
        self.cache[module] = (tool, payload, directory, package, payload_info["sha256"], pin)
        return self.cache[module]

    def read(self, path, limit):
        _, apex, module, kind, filename = path.split("/")
        require(apex == "apex" and kind == "javalib" and module in self.specs and
                re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:jar|dex)", filename),
                "Unmapped or unsupported APEX classpath member")
        tool, payload, directory, _, _, _ = self.open(module)
        return ext4_member(tool, payload, "/javalib/"+filename, limit, directory)

    def verify_unchanged(self):
        for _, payload, _, package, payload_pin, package_pin in self.cache.values():
            require(digest(payload, MAX_PAYLOAD)["sha256"] == payload_pin and
                    digest(package, MAX_APEX)["sha256"] == package_pin,
                    "Private APEX input changed")
