#!/usr/bin/env python3
"""Read selected donor files with debugfs, never mount or execute an image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from r800_vendor_inputs import image_info, MAX_IMAGE
from r800_peripheral_firmware import REQUIRED, check_bytes

MAX_FILE = 64 * 1024**2
HCD = "BCM43012B0_002.001.021.0153.0156.hcd"
# Resolved regular glibc files rather than guest symlinks. Candidate locations
# are explicit; different donor layouts are reported missing, not guessed.
TIZEN = {
    "tizen/libc.so.6": ("/lib/libc-2.24.so", "/usr/lib/libc-2.24.so"),
    "tizen/libdl.so.2": ("/lib/libdl-2.24.so", "/usr/lib/libdl-2.24.so"),
    "tizen/libpthread.so.0": ("/lib/libpthread-2.24.so", "/usr/lib/libpthread-2.24.so"),
    "tizen/ld-linux.so.3": ("/lib/ld-2.24.so", "/usr/lib/ld-2.24.so"),
    "payload/fw/bt/" + HCD: ("/usr/lib/firmware/" + HCD,),
    "payload/fw/bcmdhd_sta.bin": ("/usr/lib/firmware/bcmdhd_sta.bin",),
    "payload/fw/nvram_net.txt": ("/usr/lib/firmware/nvram_net.txt",),
    "payload/fw/bcmdhd_clm.blob": ("/usr/lib/firmware/bcmdhd_clm.blob",),
}
TIZEN.update({"payload/"+name: ("/usr/lib/firmware/"+name.removeprefix("fw/"),)
              for name in REQUIRED})
VENDOR_NAMES = (
    "lib/libeffectsconfig.so",
    "bin/hw/android.hardware.sensors@1.0-service",
    "lib/hw/android.hardware.sensors@1.0-impl.so",
    "lib/android.hardware.sensors@1.0.so",
    "bin/hw/android.hardware.gnss@1.0-service",
    "lib/hw/android.hardware.gnss@1.0-impl.so",
    "lib/android.hardware.gnss@1.0.so",
    "etc/init/android.hardware.gnss@1.0-service.rc",
    "bin/hw/android.hardware.wifi@1.0-service",
    "etc/init/android.hardware.wifi@1.0-service.rc",
    "bin/hw/wpa_supplicant", "etc/init/wpa_supplicant.rc",
    "lib/android.hardware.wifi@1.0.so",
    "lib/android.hardware.wifi.supplicant@1.0.so",
)
TIZEN_GPS = {name: paths for name, paths in TIZEN.items() if name.startswith("tizen/")}
VENDOR_IDENTITY_FILES = ("build.prop", "default.prop", "etc/vintf/manifest.xml",
                         "bin/vndservicemanager") + VENDOR_NAMES
VENDOR_PROPERTIES = frozenset((
    "ro.product.vendor.brand", "ro.product.vendor.manufacturer",
    "ro.product.vendor.model", "ro.product.vendor.device", "ro.product.vendor.name",
    "ro.vendor.build.fingerprint", "ro.vendor.build.id", "ro.vendor.build.version.sdk",
    "ro.vendor.build.version.release", "ro.board.platform", "ro.product.cpu.abilist",
    "ro.product.vendor.cpu.abilist", "ro.vndk.version",
))
PROFILES = {"tizen": TIZEN, "tizen-gps": TIZEN_GPS,
            "vendor": {"vendor/"+n: ("/"+n,) for n in VENDOR_NAMES},
            "vendor-identity": {"vendor/"+n: ("/"+n,) for n in VENDOR_IDENTITY_FILES}}


# Match the 1.0 HIDL service contracts used by build_vendor.sh.
VINTF_REQUIRED = {
    "wifi": (("android.hardware.wifi", "IWifi"),
             ("android.hardware.wifi.supplicant", "ISupplicant")),
    "sensors": (("android.hardware.sensors", "ISensors"),),
    "gnss": (("android.hardware.gnss", "IGnss"),),
}


def vintf_inventory(path):
    """Inspect one bounded device manifest; no XML includes or external entities."""
    import xml.etree.ElementTree as ET
    from r800_android_userspace_preflight import read_regular
    try:
        raw = read_regular(path, 1024 * 1024)
        # Restrict to UTF-8 before parsing so alternate encodings cannot
        # bypass the DTD/entity prohibition.
        xml = raw.decode("utf-8-sig")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml, re.IGNORECASE):
            raise ValueError("DTD or entity declaration is not allowed")
        root = ET.fromstring(xml)
        if root.tag != "manifest" or root.get("type") != "device":
            raise ValueError("Expected device VINTF manifest")
        declarations = set()
        for hal in root.findall("hal"):
            if hal.get("format", "hidl") != "hidl" or hal.findtext("transport") != "hwbinder":
                continue
            name = (hal.findtext("name") or "").strip()
            for version in hal.findall("version"):
                if (version.text or "").strip() != "1.0":
                    continue
                for interface in hal.findall("interface"):
                    iface = (interface.findtext("name") or "").strip()
                    if any((i.text or "").strip() == "default" for i in interface.findall("instance")):
                        declarations.add((name, iface))
            for fqname in hal.findall("fqname"):
                match = re.fullmatch(r"@1\.0::([A-Za-z0-9_]+)/default", (fqname.text or "").strip())
                if match:
                    declarations.add((name, match[1]))
        missing = {group: [name + "@1.0::" + iface + "/default"
                           for name, iface in required if (name, iface) not in declarations]
                   for group, required in VINTF_REQUIRED.items()}
        return {"status": "DECLARATIONS_PRESENT" if not any(missing.values()) else "REVIEW_REQUIRED",
                "missing_by_group": missing, "compatibility_verified": False}
    except (OSError, ValueError, ET.ParseError) as exc:
        return {"status": "REVIEW_REQUIRED", "reason": str(exc),
                "compatibility_verified": False}


# This is an identification checklist, not a list of supported devices.
IDENTITY_REQUIRED = ("ro.product.vendor.model", "ro.product.vendor.device",
                     "ro.vendor.build.id", "ro.vendor.build.fingerprint")
FINGERPRINT = re.compile(
    r"(?P<brand>[^/:\s]+)/(?P<product>[^/:\s]+)/(?P<device>[^/:\s]+):"
    r"(?P<release>[^/:\s]+)/(?P<build_id>[^/:\s]+)/(?P<incremental>[^/:\s]+):"
    r"(?P<type>[^/:\s]+)/(?P<tags>[^/:\s]+)")


def identity_inventory(properties, conflicts):
    """Report observed identity completeness and contradictions only."""
    missing = [key for key in IDENTITY_REQUIRED if not properties.get(key)]
    problems = ["Conflicting property: " + key for key in sorted(set(conflicts))]
    fingerprint = properties.get("ro.vendor.build.fingerprint")
    fields = {}
    if fingerprint:
        match = FINGERPRINT.fullmatch(fingerprint)
        if not match:
            problems.append("Unrecognized fingerprint format")
        else:
            fields = match.groupdict()
            for field, key in (("brand", "ro.product.vendor.brand"),
                               ("device", "ro.product.vendor.device"),
                               ("build_id", "ro.vendor.build.id"),
                               ("release", "ro.vendor.build.version.release")):
                if key in properties and properties[key] != fields[field]:
                    problems.append("Fingerprint differs from " + key)
    sdk = properties.get("ro.vendor.build.version.sdk")
    if sdk is not None and not re.fullmatch(r"[1-9][0-9]{0,2}", sdk):
        problems.append("Unrecognized vendor SDK")
    return {"status": "IDENTITY_FIELDS_PRESENT" if not missing and not problems else "REVIEW_REQUIRED",
            "missing": missing, "problems": problems, "fingerprint_fields": fields,
            "identity_verified": False, "donor_authenticity_verified": False,
            "compatibility_verified": False, "safe_to_flash": False}


def hidl_dependency_inventory(elf, names):
    """Classify direct dependencies in the selected donor inventory only.

    /vendor/lib is the explicit candidate directory for ARM32 here.
    Never infer Android namespace resolution or treat lib/hw as a search path.
    """
    objects = sorted(n for n in names if n.startswith("vendor/bin/") or n.endswith(".so"))
    edges, review = [], []
    for name in objects:
        info = elf.get(name)
        if not info or info["status"] != "ARM32_DYNAMIC":
            review.append({"object": name, "reason": "Missing or invalid ELF"})
            continue
        if info["custom_search_path"]:
            review.append({"object": name, "reason": "RPATH/RUNPATH requires review"})
        for dep in sorted(info["needed"]):
            candidate = "vendor/lib/" + dep
            provider = elf.get(candidate)
            if provider is None:
                status = "OUTSIDE_SELECTED_INVENTORY"
            elif (provider["status"] != "ARM32_DYNAMIC" or
                  provider["elf_type"] != "ET_DYN" or
                  provider["soname"] not in (None, dep)):
                status = "CANDIDATE_REJECTED"
            elif candidate in names:
                status = "SAME_GROUP_CANDIDATE"
            else:
                status = "OTHER_GROUP_CANDIDATE"
            edges.append({"from": name, "needed": dep, "candidate": candidate,
                          "status": status})
    return {"status": "DIRECT_INVENTORY_ONLY" if not review and all(
                e["status"] == "SAME_GROUP_CANDIDATE" for e in edges) else "REVIEW_REQUIRED",
            "objects": objects, "edges": edges, "elf_review": review,
            "external_names": sorted({e["needed"] for e in edges
                                      if e["status"] == "OUTSIDE_SELECTED_INVENTORY"}),
            "dependency_closure_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def vendor_identity(tree, files):
    """Report observed identity and group completeness, not donor compatibility."""
    from r800_android_linker_audit import inspect
    properties = {}
    conflicts = []
    for name in ("vendor/build.prop", "vendor/default.prop"):
        if files[name]["status"] != "EXTRACTED":
            continue
        p = tree / name
        if p.stat().st_size > 1024 * 1024:
            raise ValueError("Vendor properties exceed byte budget")
        for line in p.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not sep or key not in VENDOR_PROPERTIES:
                continue
            if not value or len(value) > 512 or not value.isprintable():
                raise ValueError("Invalid vendor property: " + key)
            if key in properties and properties[key] != value:
                conflicts.append(key)
            else:
                properties[key] = value
    elf = {}
    for name, row in files.items():
        if not (name.endswith(".so") or name.startswith("vendor/bin/")):
            continue
        if row["status"] != "EXTRACTED":
            continue
        try:
            info = inspect((tree / name).read_bytes())
            elf[name] = {"status": "ARM32_DYNAMIC" if info["abi"] == "arm" and
                         info["has_dynamic"] and (not name.endswith(".so") or
                         info["elf_type"] == "ET_DYN") else "REVIEW_REQUIRED",
                         "abi": info["abi"], "elf_type": info["elf_type"],
                         "needed": info["needed"], "soname": info["soname"],
                         "custom_search_path": info["custom_search_path"]}
        except (ValueError, KeyError) as exc:
            elf[name] = {"status": "REJECTED", "reason": str(exc)}
    groups = {}
    for group in ("wifi", "sensors", "gnss"):
        names = ["vendor/"+n for n in VENDOR_NAMES if
                 ("hardware."+group+"@" in n or
                  (group == "wifi" and ("wpa_supplicant" in n or "hardware.wifi.supplicant@" in n)))]
        missing = [n for n in names if files[n]["status"] != "EXTRACTED"]
        invalid = [n for n in names if n in elf and elf[n]["status"] != "ARM32_DYNAMIC"]
        groups[group] = {"missing": missing, "elf_review": invalid,
                         "inventory_complete": not missing and not invalid,
                         "direct_dependencies": hidl_dependency_inventory(elf, names)}
    manifest = "vendor/etc/vintf/manifest.xml"
    vintf = vintf_inventory(tree / manifest) if files[manifest]["status"] == "EXTRACTED" else {
        "status": "REVIEW_REQUIRED", "reason": "Missing device manifest",
        "compatibility_verified": False}
    return {"properties": properties, "property_conflicts": sorted(set(conflicts)),
            "identity_inventory": identity_inventory(properties, conflicts),
            "vintf": vintf,
            "elf": elf, "hidl_groups": groups,
            "vintf_manifest_present": files["vendor/etc/vintf/manifest.xml"]["status"] == "EXTRACTED",
            "identity_verified": False, "dependency_closure_verified": False,
            "runtime_verified": False, "safe_to_flash": False}



def command(tool, image, request, cwd=None):
    # debugfs opens read-only by default. No -w, no shell, no guest execution.
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([tool, "-R", request, str(image)], cwd=cwd,
                          env=env, capture_output=True, text=True, timeout=60,
                          check=True)


def locate(tool, image, guest):
    if not re.fullmatch(r"/[A-Za-z0-9_./@+-]+", guest) or ".." in guest.split("/"):
        raise ValueError("Invalid guest path")
    result = command(tool, image, "stat " + guest)
    if "File not found" in result.stderr:
        return None
    match = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)", result.stdout)
    size = re.search(r"\bSize:\s+(\d+)", result.stdout)
    if not match or not size or match[2] != "regular":
        raise ValueError("Expected regular donor file: " + guest)
    length = int(size[1])
    if not 0 < length <= MAX_FILE:
        raise ValueError("Donor file size out of bounds: " + guest)
    return int(match[1]), length


MAX_WALK_OBJECTS = 128
MAX_WALK_BYTES = 128 * 1024**2
MAX_WALK_DEPTH = 16
MAX_WALK_EDGES = 4096


def vendor_dependency_walk(tool, snapshot, scratch, tree, files):
    """Bounded ARM32 vendor/lib candidate graph, not Android resolution.

    Read only from the same verified snapshot, retain only metadata for
    additional dependencies. Missing providers may be in system/VNDK.
    """
    from collections import deque
    from r800_android_linker_audit import inspect
    roots = sorted(name for name, row in files.items()
                   if row["status"] == "EXTRACTED" and
                   (name.startswith("vendor/bin/") or name.endswith(".so")))
    pending = deque((name, 0) for name in roots)
    objects, edges, problems = {}, [], []
    total = 0
    exhausted = False
    while pending:
        name, depth = pending.popleft()
        if name in objects:
            continue
        if len(objects) >= MAX_WALK_OBJECTS or depth > MAX_WALK_DEPTH:
            problems.append("Object or depth budget exceeded")
            exhausted = True
            break
        objects[name] = {"status": "REVIEW_REQUIRED"}
        try:
            if name in files and files[name]["status"] == "EXTRACTED":
                raw = (tree / name).read_bytes()
                if hashlib.sha256(raw).hexdigest() != files[name]["sha256"]:
                    raise ValueError("Selected member digest mismatch")
                if total + len(raw) > MAX_WALK_BYTES:
                    exhausted = True
                    raise ValueError("Byte budget exceeded")
            else:
                found = locate(tool, snapshot, "/" + name.removeprefix("vendor/"))
                if found is None:
                    objects[name] = {"status": "OUTSIDE_VENDOR_LIB"}
                    continue
                inode, length = found
                if total + length > MAX_WALK_BYTES:
                    exhausted = True
                    raise ValueError("Byte budget exceeded")
                target = scratch / "dependency-member"
                try:
                    command(tool, snapshot, "dump <%d> dependency-member" % inode, cwd=scratch)
                    st = target.lstat()
                    if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                        raise ValueError("Dependency size mismatch")
                    raw = target.read_bytes()
                finally:
                    target.unlink(missing_ok=True)
            total += len(raw)
            info = inspect(raw)
            if info["abi"] != "arm" or not info["has_dynamic"]:
                raise ValueError("Expected dynamic ARM32 ELF")
            if name.endswith(".so") and (info["elf_type"] != "ET_DYN" or
                    info["soname"] not in (None, name.rsplit("/", 1)[-1])):
                raise ValueError("Invalid shared object type or SONAME")
            if info["custom_search_path"]:
                raise ValueError("RPATH/RUNPATH requires review")
            objects[name] = {"status": "CANDIDATE_ONLY", "sha256": hashlib.sha256(raw).hexdigest(),
                             "bytes": len(raw), "needed": info["needed"], "depth": depth}
            for dep in sorted(info["needed"]):
                if len(edges) >= MAX_WALK_EDGES:
                    exhausted = True
                    raise ValueError("Edge budget exceeded")
                if not re.fullmatch(r"[A-Za-z0-9_@.+~-]{1,255}", dep) or dep in (".", ".."):
                    raise ValueError("Invalid DT_NEEDED basename")
                candidate = "vendor/lib/" + dep
                edges.append({"from": name, "needed": dep, "candidate": candidate})
                pending.append((candidate, depth + 1))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            objects[name] = {"status": "REVIEW_REQUIRED", "reason": str(exc)}
            problems.append(name + ": " + str(exc))
            if exhausted:
                break
    for edge in edges:
        edge["status"] = objects.get(edge["candidate"], {}).get("status", "NOT_INSPECTED")
    external = sorted({e["needed"] for e in edges if e["status"] == "OUTSIDE_VENDOR_LIB"})
    return {"status": "VENDOR_LIB_CANDIDATES_ONLY" if roots and not problems and not external and
            all(o["status"] == "CANDIDATE_ONLY" for o in objects.values()) else "REVIEW_REQUIRED",
            "roots": roots, "objects": objects, "edges": edges, "external_names": external,
            "problems": problems, "budget_exhausted": exhausted, "bytes_inspected": total,
            "dependency_closure_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def snapshot_image(image, snapshot, expected_sha):
    """Copy bounded bytes once; debugfs never reopens the mutable donor path."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    initial = image.lstat()
    if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= MAX_IMAGE:
        raise ValueError("Expected bounded regular donor image")

    def identity(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                s.st_mtime_ns, s.st_ctime_ns)

    digest = hashlib.sha256()
    count = 0
    with os.fdopen(os.open(image, flags), "rb") as src:
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed before snapshot")
        with snapshot.open("xb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                count += len(block)
                if count > initial.st_size:
                    raise ValueError("Donor size changed")
                digest.update(block)
                dst.write(block)
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed during snapshot")
    if count != initial.st_size or identity(image.lstat()) != identity(initial):
        raise ValueError("Donor changed during snapshot")
    if digest.hexdigest() != expected_sha:
        raise ValueError("Input image SHA-256 mismatch")
    snapshot.chmod(0o400)
    return identity(initial)


def extract(image, output, profile, expected_sha):
    image, output = Path(image).absolute(), Path(output).absolute()
    if profile not in PROFILES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Expected donor profile and SHA-256")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("Install e2fsprogs (debugfs)")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        scratch = Path(tmp)
        snapshot = scratch/"donor.img"
        source_identity = snapshot_image(image, snapshot, expected_sha)
        before = image_info(snapshot)
        if before["sha256"] != expected_sha:
            raise ValueError("Snapshot SHA-256 mismatch")
        tree = scratch/"files"
        tree.mkdir()
        files = {}
        for dest, candidates in PROFILES[profile].items():
            matches = []
            for guest in candidates:
                found = locate(tool, snapshot, guest)
                if found is not None:
                    matches.append((guest, found))
            if not matches:
                files[dest] = {"status": "MISSING", "candidates": list(candidates)}
                continue
            if len({m[1][0] for m in matches}) > 1:
                files[dest] = {"status": "AMBIGUOUS", "candidates": [m[0] for m in matches]}
                continue
            guest, (inode, length) = matches[0]
            target = scratch/"member"
            command(tool, snapshot, "dump <%d> member" % inode, cwd=scratch)
            st = target.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                raise ValueError("Extracted donor size mismatch: " + guest)
            raw = target.read_bytes()
            if dest.removeprefix("payload/") in REQUIRED:
                check_bytes(dest.removeprefix("payload/"), raw)
            destpath = tree/dest
            destpath.parent.mkdir(parents=True, exist_ok=True)
            os.rename(target, destpath)
            destpath.chmod(0o644)
            files[dest] = {"status":"EXTRACTED", "source":guest,
                           "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        dependency_walk = None
        if profile == "vendor-identity":
            dependency_walk = vendor_dependency_walk(tool, snapshot, scratch, tree, files)
        current = image.lstat()
        if (current.st_dev, current.st_ino, current.st_mode, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != source_identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot) != before:
            raise ValueError("Donor snapshot changed")
        report = {"status":"EXT4_DONOR_EXTRACTION_ONLY","profile":profile,
                  "image_sha256":expected_sha,"snapshot_verified":True,"files":files,
                  "missing_or_ambiguous":[n for n,v in files.items() if v["status"]!="EXTRACTED"],
                  "donor_compatibility_verified":False,"xattrs_preserved":False,
                  "safe_to_flash":False}
        if profile == "vendor-identity":
            report["vendor_identity"] = vendor_identity(tree, files)
            report["vendor_identity"]["vendor_dependency_walk"] = dependency_walk
        (tree/"ext4-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True))
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    p.add_argument("--sha256",required=True)
    a=p.parse_args()
    report=extract(a.image,a.output,a.profile,a.sha256)
    print(json.dumps(report,sort_keys=True))
    identity = report.get("vendor_identity", {})
    review = identity.get("property_conflicts") or any(
        item["status"] != "ARM32_DYNAMIC" for item in identity.get("elf", {}).values())
    review = review or (identity and identity["vintf"]["status"] != "DECLARATIONS_PRESENT")
    review = review or (identity and identity["identity_inventory"]["status"] != "IDENTITY_FIELDS_PRESENT")
    return 2 if report["missing_or_ambiguous"] or review else 0


if __name__=="__main__":
    raise SystemExit(main())
