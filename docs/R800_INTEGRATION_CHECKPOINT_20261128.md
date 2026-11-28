# GalWearOS SM-R800: confirmed integration checkpoint and next inputs

Evidence checkpoint: a9232cfe160209fb76e734dab415ec75b0426d8b, 2026-11-28.
This is historical exact-head evidence, not a claim about subsequent commits.

## Confirmed by GitHub Actions

- Integrated regression job 140988009088, run 46147946582: 2235 tests, OK, no skips.
- Offline validation job 140988009169, run 46147946595: 2235 discovered/executed by unittest, OK (skipped=10), not equivalent to the no-skip regression.
- HAL compile job 140988008923: five HALs compiled; BusyBox/Wi-Fi built; component tree 45 files; device layer 39 files; vendor recipe overlay 11 files; reference GPS runtime subset 5 files.
- ARM32 Bionic QEMU job 140988008737: synthetic HAL, EGL, HWC, Audio, Sensors, GPS and Lights probes passed.
- Functional development initramfs compiled and CPIO staged. This does not establish kernel Image compilation or Android handover.
- Independent overlay and reference cross-host jobs passed.
- Four other workflows: recovery readiness 46147946624, kernel power 46147946605, kernel preflight 46147946604, provenance 46147946593 passed.
- The optional kernel job was skipped. No physical test, full vendor assembly, or release.

## Actual next input boundary

The empty-donor CI check deliberately reported EXPECTED_DONOR_HOLD with 35
missing entries. This is a broad legacy payload inventory, not 35 mandatory
independent downloads for the managed development build. Some entries are
generated assets, some are files inside the same donor.

The managed development builder (r800_build_local_development.py) instead
requires these nine explicit roles:

| Role | Source / evidence required |
| --- | --- |
| kernel | same-head functional kernel build directory; development-kernel-evidence.json pin |
| components | same-head compiled component directory; component-evidence.json pin |
| system | pinned raw EXT4 from Pixel Watch r11btwifi RWDC.230905.003 Android 11; extraction report |
| base | historical base vendor raw EXT4, literal identity review |
| j4 | SM-J400F Android 9 raw vendor EXT4; stock extraction report and archive pin |
| effects | selected libeffectsconfig.so and SHA-256, origin still needs review |
| tizen | SM-R800 stock root filesystem raw EXT4; extraction report and archive pin |
| closure | prepared Tizen dependency-closure directory and manifest pin |
| ndk | r27c installed tools and selected tool pins |

Managed mode also requires the Linux assembly lock, successful synthetic
mount probe and static host ELF lock. Optional display assets are a separate
input. The 35-entry legacy audit additionally covers combination/boot
templates, radio/peripheral firmware, display files and curated runtime
directories; a complete installation payload is not equivalent to a
development tree. Never substitute the Debian reference for the Tizen donor.

## Execution order

1. Reproduce same-head components and functional kernel in a dedicated
   trusted Ubuntu 24.04 VM, without releasing proprietary inputs or binaries.
2. Obtain the exact Android 11 Pixel archive and authorized stock inputs;
   record hashes and extract only the selected partitions. Android 15
   BW1A.251005.003.W1 is reference-only for this pipeline.
3. Establish base vendor identity and effects provenance; prepare Tizen
   dependency closure. Do not invent missing stock files.
4. Run managed check, then the explicit local development builder and its
   independent readiness review. Keep installation/recovery gates separate.

No VM, donor acquisition or full donor-backed build was performed by this
checkpoint. The successful runner built and tested selected components;
only evidence was uploaded. Do not label the integrated development tree
as produced. ready_to_build=false until local inputs and environment are
validated; safe_to_flash=false.

CI links:
- https://github.com/vorlocsev/galwear/actions/runs/46147946582
- https://github.com/vorlocsev/galwear/actions/runs/46147946595
