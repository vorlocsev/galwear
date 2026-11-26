# Extract R800 GNSS donor files from an offline ext4 image

This procedure requires a trusted, already extracted ext4 filesystem
image of the Tizen root and e2fsprogs (debugfs). The expected SHA-256
must come from the intended input; calculating it locally binds the
operation to those bytes but does not authenticate firmware provenance.
Do not pass a whole flash image, compressed archive, or live partition.

```sh
sha256sum /path/to/rootfs.img
PYTHONDONTWRITEBYTECODE=1 python3 build/r800_extract_ext4.py \
  --image /path/to/rootfs.img --output /path/to/gnss-extracted \
  --profile gps-gnss --sha256 EXPECTED_SHA256
```

Replace EXPECTED_SHA256 with the intended 64-character lowercase digest.
The output directory must not exist. The extractor uses a verified
private image snapshot and read-only debugfs commands.

The new gps-gnss profile contains the four gps-glibc entries plus
/usr/lib/libbrcm.so, written as tizen/libbrcm.so. No coordinate caches,
user files, or other runtime state are included. A missing library is
recorded as MISSING; conflicting candidates or unresolved symbolic links
are not silently accepted. A partial extraction can exist when the
command exits 2. Review ext4-evidence.json before use.

The extracted tizen directory may be supplied to the existing glibc
link gate once the GPS bridge has been built. The Broadcom file is not
needed for the synthetic QEMU glibc probe. Extraction alone does not
verify ELF ABI, the gps_get_hardware_interface export, its dependency
closure or runtime. The existing r800_tizen_gnss_preflight.py requires
an isolated full donor filesystem tree, not this five-file output.

## Verification status

2026-11-26: three new ext4 test methods added for successful Broadcom
extraction, a missing Broadcom file, and an unresolved Broadcom symlink.
The existing ext4 test suite is already part of the full GPS offline gate.
The local execution environment has neither debugfs nor mkfs.ext4 on
PATH; git ls-remote failed with a DNS resolution error for github.com.
The new ext4 tests have NOT been executed. No original donor image was
provided or extracted. No CI or runtime result is claimed.

HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
