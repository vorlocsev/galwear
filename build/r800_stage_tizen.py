#!/usr/bin/env python3
"""Stage only the verified Tizen ELF closure; not a runnable chroot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from r800_tizen_dependencies import audit, resolve_guest, TARGETS, MAX_FILE, MAX_TOTAL
from r800_android_userspace_preflight import read_regular


def stage(root, output, targets=TARGETS):
    root = root.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if output.resolve().is_relative_to(root):
        raise ValueError("Output must be outside donor tree")
    report = audit(root, targets)
    if report["problems"]:
        raise ValueError("Unresolved Tizen dependency closure")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tree = Path(tmp)/"tizen-elf"
        tree.mkdir()
        inventory = {}
        total = 0
        # Flatten only known guest aliases to regular copies. No symlinks or
        # privileged modes are transferred. This is a library staging tree,
        # not a substitute for the original Tizen configuration or permissions.
        paths = dict(report["aliases"])
        paths.update({name:name for name in report["files"]})
        for guest, canonical in sorted(paths.items()):
            source, actual = resolve_guest(root, guest)
            if actual != canonical:
                raise ValueError("Donor alias changed")
            data = read_regular(source, MAX_FILE)
            expected = report["files"][canonical]
            sha = hashlib.sha256(data).hexdigest()
            if len(data) != expected["bytes"] or sha != expected["sha256"]:
                raise ValueError("Donor ELF changed")
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError("Staging byte budget exceeded")
            mode = 0o755 if source.stat().st_mode & stat.S_IXUSR else 0o644
            dest = tree/guest.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as out:
                out.write(data)
            dest.chmod(mode)
            inventory[guest] = {"source":canonical,"bytes":len(data),"sha256":sha,"mode":oct(mode)}
        result = {"status":"TIZEN_ELF_SUBSET_ONLY","files":inventory,
                  "version_records_checked":report["version_records_checked"],
                  "configuration_complete":False,"plugins_complete":False,
                  "ownership_preserved":False,"runtime_verified":False,
                  "safe_to_flash":False}
        (tree/"tizen-elf-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True))
        os.rename(tree,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(stage(a.root,a.output),sort_keys=True))


if __name__=="__main__":
    main()
