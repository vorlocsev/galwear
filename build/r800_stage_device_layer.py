#!/usr/bin/env python3
"""Assemble the same-head compiled GalWear device layer in its target layout.

This is a directory of real compiled components and tracked integration scripts,
not a mounted Android rootfs, complete vendor image, payload archive or firmware.
No donor bytes, persistent state, boot selection marker or guest execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import verify_components, checked
from r800_graphics_donor_binding import checkout_sha
from r800_prepare_payload_inputs import COMPILED
from r800_payload_candidate import SCRIPTS, CHARGER_TOOLS
from r800_vendor_inputs import OVERLAY
from r800_compiled_overlay_ext4 import destination
from r800_extract_super import require
from r800_display_asset_layer import load_assets

MAX_FILE = 64*1024**2
MAX_TOTAL = 512*1024**2
MISSING = (
    "android/system: original Wear OS donor and R800 adaptations",
    "vendor: compatible base/J4 donor libraries and complete VINTF/SELinux configuration",
    "r800dev/gpsbridge: linked against identified original Tizen glibc",
    "r800dev/tzlite and lib: Tizen runtime/configuration/plugins",
    "r800dev/fw: original radio and peripheral firmware",
    "r800dev/charger and splash: display assets",
    "kernel/DTB and Android handover integration",
    "hardware boot, recovery and installation acceptance",
)


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "Duplicate component manifest key")
        out[key] = value
    return out


def assemble(components, output, source_sha, *, assets=None, assets_sha=None):
    checkout_sha(source_sha)
    repo = Path(__file__).resolve().parents[1]
    components = Path(components).resolve(strict=True)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(components) and
            not output.resolve().is_relative_to(repo), "Fresh output outside input trees required")
    require((assets is None)==(assets_sha is None), "Asset directory and manifest pin must be supplied together")
    if assets is not None:
        assets=Path(assets).absolute()
        require(not output.resolve().is_relative_to(assets), "Output inside asset input")
    display=load_assets(assets,assets_sha) if assets is not None else {}
    verify_components(components, source_sha)
    manifest_raw = read_regular(checked(components, "component-evidence.json"), 1024*1024)
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)["files"]
    mapping = {}
    for name in sorted(COMPILED):
        mode = 0o755 if name.startswith("bin/") or name in CHARGER_TOOLS else 0o644
        mapping["r800dev/"+name] = ("components", "payload/"+name, mode)
    for name in sorted(OVERLAY):
        mapping["vendor/"+destination(name)] = ("components", "vendor-overlay/"+name, 0o644)
    for name in SCRIPTS:
        mapping["r800dev/"+name] = ("checkout", "payload/"+name, 0o755)
    mapping["r800dev/tzchroot.sh"] = ("checkout", "src/tools/sensors/tzchroot.sh", 0o755)
    require(all(source in manifest for origin, source, _ in mapping.values()
                if origin == "components"), "Compiled device layer missing required files")
    rows, total = {}, 0
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="r800-device-layer-") as tmp:
        stage = Path(tmp)/"tree"
        stage.mkdir()
        for name, (origin, source, mode) in sorted(mapping.items()):
            root = components if origin == "components" else repo
            raw = read_regular(checked(root, source), MAX_FILE)
            digest = hashlib.sha256(raw).hexdigest()
            if origin == "components":
                expected = manifest[source]
                require(expected["sha256"] == digest and expected["bytes"] == len(raw) and
                        expected["mode"] == oct(mode), "Component bytes or mode changed: "+source)
            total += len(raw)
            require(total <= MAX_TOTAL, "Device layer aggregate budget exceeded")
            path = stage/name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
            path.chmod(mode)
            rows[name] = {"origin": origin, "source": source, "sha256": digest,
                          "bytes": len(raw), "mode": oct(mode)}
        for name, raw in sorted(display.items()):
            require(name not in rows,"Display asset collides with compiled device member")
            total += len(raw)
            require(total <= MAX_TOTAL,"Device layer aggregate budget exceeded")
            path=stage/name
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
            path.chmod(0o644)
            rows[name]={"origin":"local_asset_conversion","source":name.removeprefix("r800dev/"),
                        "sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"mode":"0o644"}
        if assets is not None:
            require(load_assets(assets,assets_sha)==display,"Asset input changed")
        # The same HAL bytes must be installed in both legacy and vendor paths.
        for name in ("audio.primary.r800.so", "gps.r800.so", "hwcomposer.r800.so", "sensors.r800.so"):
            require(rows["vendor/lib/hw/"+name]["sha256"] == rows["r800dev/hwc/"+name]["sha256"],
                    "HAL copies disagree: "+name)
        require(rows["r800dev/bin/wpcd"]["sha256"] == rows["r800dev/charger/wpcd"]["sha256"],
                "WPCD copies disagree")
        for name, row in rows.items():
            path = stage/name
            raw = read_regular(path, MAX_FILE)
            require(hashlib.sha256(raw).hexdigest() == row["sha256"] and len(raw) == row["bytes"]
                    and oct(stat.S_IMODE(path.stat().st_mode)) == row["mode"], "Staged file mismatch")
        verify_components(components, source_sha)
        require(read_regular(components/"component-evidence.json", 1024*1024) == manifest_raw,
                "Component manifest changed")
        checkout_sha(source_sha)
        report = {"schema": "galwear-r800-device-layer-v1",
                  "status": "COMPILED_DEVICE_LAYER_STAGED_ONLY", "source_sha": source_sha,
                  "component_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                  "files": rows, "total_bytes": total, "assets_manifest_sha256":assets_sha,
                  "missing_inputs_and_gates": [n for n in MISSING if not display or n!="r800dev/charger and splash: display assets"],
                  "donor_images_used": False, "complete_vendor_built": False,
                  "android_handover_tested": False, "payload_complete": False,
                  "hardware_tested": False, "safe_to_flash": False}
        (stage/"device-layer-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(), "Output already exists")
        os.rename(stage, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--components", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--assets",type=Path)
    p.add_argument("--assets-sha256")
    a = p.parse_args()
    report = assemble(a.components, a.output, a.source_sha, assets=a.assets,assets_sha=a.assets_sha256)
    print(report["status"], len(report["files"]), "files; safe_to_flash=false")


if __name__ == "__main__":
    main()
