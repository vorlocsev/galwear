#!/usr/bin/env python3
"""Read-only mandatory donor recipe path audit; no mounts or guest execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_extract_ext4 import snapshot_image, command
from r800_vendor_inputs import image_info
from r800_android_userspace_preflight import read_regular
from r800_android_linker_audit import inspect

BASE_PATHS = ["bin/hw/android.hardware.configstore@1.1-service","bin/hw/android.hardware.graphics.allocator@2.0-service","bin/hw/android.hardware.health@2.0-service","bin/hw/android.hardware.power@1.0-service","bin/vndservicemanager","build.prop","default.prop","etc/fs_config_dirs","etc/fs_config_files","etc/group","etc/init/android.hardware.configstore@1.1-service.rc","etc/init/android.hardware.graphics.allocator@2.0-service.rc","etc/init/android.hardware.health@2.0-service.rc","etc/init/android.hardware.power@1.0-service.rc","etc/init/vndservicemanager.rc","etc/media_codecs.xml","etc/media_codecs_google_audio.xml","etc/media_codecs_google_telephony.xml","etc/media_profiles_vendor.xml","etc/passwd","etc/permissions","etc/seccomp_policy","etc/selinux","etc/vintf","lib/hw/android.hardware.graphics.allocator@2.0-impl.so","lib/hw/android.hardware.graphics.mapper@2.0-impl.so","lib/hw/android.hardware.power@1.0-impl.so","lib/hw/gralloc.default.so","lib/hw/power.default.so","lib/libhwminijail.so"]
J4_PATHS = ["bin/hw/android.hardware.audio@2.0-service","bin/hw/android.hardware.bluetooth@1.0-service","bin/hw/android.hardware.gatekeeper@1.0-service","bin/hw/android.hardware.graphics.allocator@2.0-service","bin/hw/android.hardware.graphics.composer@2.1-service","bin/hw/android.hardware.keymaster@3.0-service","bin/hw/android.hardware.memtrack@1.0-service","bin/hw/vendor.samsung.hardware.light@2.0-service","etc/init/android.hardware.audio@2.0-service.rc","etc/init/android.hardware.bluetooth@1.0-service.rc","etc/init/android.hardware.gatekeeper@1.0-service.rc","etc/init/android.hardware.graphics.allocator@2.0-service.rc","etc/init/android.hardware.graphics.composer@2.1-service.rc","etc/init/android.hardware.keymaster@3.0-service.rc","etc/init/android.hardware.memtrack@1.0-service.rc","etc/init/vendor.samsung.hardware.light@2.0-service.rc","lib/android.hardware.audio.common-util.so","lib/android.hardware.audio.common@2.0-util.so","lib/android.hardware.audio.common@2.0.so","lib/android.hardware.audio.common@4.0.so","lib/android.hardware.audio.effect@2.0.so","lib/android.hardware.audio.effect@4.0.so","lib/android.hardware.audio@2.0.so","lib/android.hardware.audio@4.0.so","lib/android.hardware.bluetooth.a2dp@1.0.so","lib/android.hardware.gatekeeper@1.0.so","lib/android.hardware.keymaster@3.0.so","lib/android.hardware.soundtrigger@2.0.so","lib/android.hardware.soundtrigger@2.1.so","lib/egl/libGLES_mali.so","lib/hw/android.hardware.audio.effect@2.0-impl.so","lib/hw/android.hardware.audio@2.0-impl.so","lib/hw/android.hardware.bluetooth@1.0-impl.so","lib/hw/android.hardware.gatekeeper@1.0-impl.so","lib/hw/android.hardware.graphics.allocator@2.0-impl.so","lib/hw/android.hardware.graphics.composer@2.1-impl.so","lib/hw/android.hardware.graphics.mapper@2.0-impl.so","lib/hw/android.hardware.keymaster@3.0-impl.so","lib/hw/android.hardware.memtrack@1.0-impl.so","lib/hw/audio.primary.default.so","lib/hw/audio.primary.universal7570.so","lib/hw/audio.r_submix.default.so","lib/hw/audio.usb.default.so","lib/hw/gatekeeper.exynos7570.so","lib/hw/gralloc.exynos5.so","lib/hw/memtrack.universal7570.so","lib/hw/vendor.samsung.hardware.light@2.0-impl.so","lib/libSamsungPostProcessConvertor.so","lib/libaudio-ril.so","lib/libaudioroute.so","lib/libbt-vendor.so","lib/libeffects.so","lib/libfloatingfeature.so","lib/libfmq.so","lib/libhwc2on1adapter.so","lib/libhwc2onfbadapter.so","lib/libion_exynos.so","lib/libkeymaster3device.so","lib/libkeymaster_portable.so","lib/libpreprocessing_nxp.so","lib/libpuresoftkeymasterdevice.so","lib/librecordalive.so","lib/libsamsungDiamondVoice.so","lib/libsecaudioinfo.so","lib/libskeymaster3device.so","lib/libsoftkeymasterdevice.so","lib/libtinyalsa.so","lib/libtinycompress.so","lib/libvndsecril-client.so","lib/vendor.samsung.hardware.bluetooth@1.0.so","lib/vendor.samsung.hardware.light@2.0.so"]
DIRECTORIES = ["etc/selinux","etc/vintf","etc/seccomp_policy","etc/permissions"]
GROUPS = {"wifi":["bin/hw/android.hardware.wifi@1.0-service","bin/hw/wpa_supplicant","etc/init/android.hardware.wifi@1.0-service.rc","etc/init/wpa_supplicant.rc","lib/android.hardware.wifi.supplicant@1.0.so","lib/android.hardware.wifi@1.0.so"],"sensors":["bin/hw/android.hardware.sensors@1.0-service","lib/android.hardware.sensors@1.0.so","lib/hw/android.hardware.sensors@1.0-impl.so"],"gnss":["bin/hw/android.hardware.gnss@1.0-service","etc/init/android.hardware.gnss@1.0-service.rc","lib/android.hardware.gnss@1.0.so","lib/hw/android.hardware.gnss@1.0-impl.so"]}
MAX_REGULAR = 64 * 1024**2


def inspect_path(tool, image, name):
    # Fixed recipe paths only. Reject symlinks/special files conservatively.
    if not re.fullmatch(r"[A-Za-z0-9_./@+-]+", name) or any(
            part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("Invalid recipe path")
    for parent in reversed(list(Path(name).parents)):
        if str(parent) == ".":
            continue
        output = command(tool, image, "stat /" + parent.as_posix())
        if "File not found" in output.stderr:
            return {"status": "MISSING", "parent": parent.as_posix()}
        if not re.search(r"Inode:\s+\d+\s+Type:\s+directory\b", output.stdout):
            return {"status": "REVIEW_REQUIRED", "parent": parent.as_posix()}
    output = command(tool, image, "stat /" + name)
    if "File not found" in output.stderr:
        return {"status": "MISSING"}
    match = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)", output.stdout)
    if not match:
        return {"status": "REVIEW_REQUIRED"}
    expected = "directory" if name in DIRECTORIES else "regular"
    if match[2] != expected:
        return {"status": "REVIEW_REQUIRED", "type": match[2], "expected_type": expected}
    row = {"status": "PRESENT_TYPE_ONLY", "type": expected}
    if expected == "regular":
        size = re.search(r"\bSize:\s+(\d+)", output.stdout)
        if not size or not 0 < int(size[1]) <= MAX_REGULAR:
            return {"status": "REVIEW_REQUIRED", "reason": "File size out of bounds"}
        row["bytes"] = int(size[1])
    return row


def inspect_elf(tool, image, name, row, scratch):
    if row["status"] != "PRESENT_TYPE_ONLY" or not (
            name.startswith("bin/") or name.endswith(".so")):
        return row
    target = scratch/"elf-member"
    try:
        command(tool, image, "dump /" + name + " elf-member", cwd=scratch)
        raw = read_regular(target, MAX_REGULAR)
        if len(raw) != row["bytes"]:
            raise ValueError("Extracted ELF size mismatch")
        info = inspect(raw)
        expected = ("ET_DYN",) if name.endswith(".so") else ("ET_EXEC", "ET_DYN")
        if info["abi"] != "arm" or info["elf_type"] not in expected or not info["has_dynamic"]:
            raise ValueError("Expected dynamic ARM32 ELF")
        if info["custom_search_path"]:
            raise ValueError("Unexpected custom ELF search path")
        return {**row, "status": "ELF_STRUCTURE_ONLY", "sha256": hashlib.sha256(raw).hexdigest(),
                "abi": info["abi"], "elf_type": info["elf_type"], "needed": info["needed"],
                "soname": info["soname"], "runtime_verified": False}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        return {**row, "status": "REVIEW_REQUIRED", "reason": str(exc)}
    finally:
        target.unlink(missing_ok=True)


def inventory(tool, base, j4, scratch=None):
    accepted = ("PRESENT_TYPE_ONLY", "ELF_STRUCTURE_ONLY")
    results = {}
    for label, image, fixed in (("base", base, BASE_PATHS), ("j4", j4, J4_PATHS)):
        names = sorted(set(fixed) | {name for group in GROUPS.values() for name in group})
        results[label] = {name: inspect_path(tool, image, name) for name in names}
        if scratch is not None:
            results[label] = {name: inspect_elf(tool, image, name, row, scratch)
                              for name, row in results[label].items()}
    blockers = []
    for label, fixed in (("base", BASE_PATHS), ("j4", J4_PATHS)):
        blockers.extend(label + ":" + name for name in fixed
                        if results[label][name]["status"] not in accepted)
    selections = {}
    for group, names in GROUPS.items():
        complete = [label for label in ("base", "j4") if all(
            results[label][name]["status"] in accepted for name in names)]
        selections[group] = {"complete_donors": complete,
                             "selected": complete[0] if complete else None}
        if not complete:
            blockers.append("hidl:" + group)
    return {"status": ("VENDOR_RECIPE_ELF_STRUCTURE_ONLY" if scratch is not None else
                       "VENDOR_RECIPE_PATHS_ONLY") if not blockers else "REVIEW_REQUIRED",
            "elf_checks_requested": scratch is not None,
            "fixed_required_counts": {"base": len(BASE_PATHS), "j4": len(J4_PATHS)},
            "donors": results, "hidl_groups": selections, "blockers": blockers,
            "recursive_directory_contents_verified": False, "elf_closure_verified": False,
            "donor_identity_verified": False, "selinux_compatibility_verified": False,
            "complete_vendor_image_built": False, "safe_to_flash": False}


def audit(base, base_sha, j4, j4_sha, check_elf=False):
    tool = shutil.which("debugfs")
    if not tool or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (base_sha, j4_sha)):
        raise ValueError("debugfs and two SHA-256 pins required")
    if base.resolve() == j4.resolve() or base_sha == j4_sha:
        raise ValueError("Expected distinct base and J4 donor images")
    with tempfile.TemporaryDirectory(prefix="r800-vendor-recipe-") as tmp:
        root = Path(tmp)
        a, b = root/"base.img", root/"j4.img"
        snapshot_image(base, a, base_sha)
        snapshot_image(j4, b, j4_sha)
        expected = [image_info(a), image_info(b)]
        report = inventory(tool, a, b, root if check_elf else None)
        if [image_info(a), image_info(b)] != expected or [image_info(base), image_info(j4)] != expected:
            raise ValueError("Donor changed during audit")
        report["donor_images"] = {"base": expected[0], "j4": expected[1]}
        report["snapshot_verified"] = True
        return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, required=True)
    p.add_argument("--base-sha256", required=True)
    p.add_argument("--j4", type=Path, required=True)
    p.add_argument("--j4-sha256", required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--check-elf", action="store_true")
    a = p.parse_args()
    try:
        if a.report.resolve() in (a.base.resolve(), a.j4.resolve()):
            raise ValueError("Report must not overwrite donor")
        report = audit(a.base, a.base_sha256, a.j4, a.j4_sha256, a.check_elf)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("VENDOR_RECIPE_PATHS_ONLY", "VENDOR_RECIPE_ELF_STRUCTURE_ONLY") else 2


if __name__ == "__main__":
    raise SystemExit(main())
