# Prepare local Tizen glibc inputs for GPS checks

Use a trusted, immutable, extracted R800 Tizen root on Linux, not a live
filesystem. The output directory must not already exist, must be outside
the donor root, and its parent must exist.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/r800_stage_gps_donors.py --root /path/to/tizen-root --output /path/to/gps-donors
```

The tool resolves guest library paths using resolve_guest, checks ELF/SONAME
with the GPS gate, rejects conflicting copies under /lib and /usr/lib, and
writes four regular library files plus manifest.json with SHA-256 and sizes.
The manifest does not authenticate donor provenance. Use only trusted
immutable input and a private output parent; concurrent changes to the
source tree are outside the supported threat model.

The staged directory can be passed to src/tools/gps/build.sh and
build/r800_gps_glibc_qemu.sh. libbrcm.so is checked separately by
r800_tizen_gnss_preflight.py and is not part of this four-file glibc set.

## Executed host evidence

2026-11-25: isolated two-file fixture, Python unittest, 8/8 passed.
Local git hash-object outputs matched the uploaded blobs:

- 573a8a4cece0b7ad6d78b308a2ba3cfa2fc4f0d6 build/r800_stage_gps_donors.py
- 0c7f67f72490b1c51c156fb344602037fc2df653 tests/test_r800_stage_gps_donors.py

Synthetic contents and injected test resolver/SONAME validator only.
The actual CLI with the project's ELF parser and resolver was not exercised.
git ls-remote failed with DNS error; qemu-arm-static and bwrap were absent
from PATH. Previous test reports were not independently repeated.
No actual donor files, target linking, QEMU, hardware or CI verified.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
