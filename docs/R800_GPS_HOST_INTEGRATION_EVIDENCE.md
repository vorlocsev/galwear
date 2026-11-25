# R800 GPS full-source host integration evidence

Baseline: 8c637c7927a39b79f4d89922c3f7720f886112a0. The local environment cannot resolve github.com, so
source files were fetched individually and copied into the existing local
core-regression fixture. Exact Git blob hashes were checked. The baseline
bridge failed host compilation (timespec fields), and the baseline HAL
failed GCC -Werror (misleading indentation and strncpy truncation).
Both source files are corrected in this commit.

Local GCC 14.2, Clang 17, UBSan, 2026-11-25:
- GPS core script rerun: PASS (7 C executables, 8 Python tests, 6 ABI checks).
- Full bridge host compile: PASS.
- Full bridge ARMv7 softfp object compile for XTRA 0/1/2: 3/3 PASS,
  ELF32 ARM EABI5. No target linking.
- Actual HAL lifecycle and synthetic peer fixtures: PASS, each repeated
  three additional times. Peer scenarios include fragmented fix,
  satellites, STOP/START reset, reconnect and malformed frames.
- Actual bridge plus actual HAL reader plus synthetic Broadcom DSO:
  6/6 PASS (normal bidirectional exchange, duplicate instance and crash
  recovery, existing file preserved, re-init failure, socket mode,
  STOP failure).

Exact tested modified blobs:
50ea027bac8e9163bb81bbb87efdda74d538f9d8 src/tools/gps/gpsbridge.c
fa133f1f923f19fe29b2919aa56534dcf0e5d32e src/hal/gps_r800.c

Exact tested fixture blobs:
d4a015c8220e83bb3c1614896bc4c9dc80e00f1b tests/test_r800_gps_hal_lifecycle.c
e322725185a621595551177fbcbedd86eb60eb44 tests/test_r800_gps_hal_peer.c
c0e4181ceb5247b655fe17f0b20b9c9a202159a9 tests/test_r800_gps_both_sides.c
686615c6c1c838204cdac9f01be24582048504d6 tests/r800_mock_brcm.c
04899f5aa1c34dcffbd199722decea842250104a tests/test_r800_gps_bridge_integration.py

The header and core fixture identities are documented in
R800_GPS_CORE_REGRESSION.md. No complete repository checkout, no donor
glibc final link, no Android NDK module build, no QEMU, no physical test
and no exact-head CI result. The host HAL excludes Android module
registration; this evidence does not verify the binary Android ABI.
The remaining static donor and userspace Python tests have not been run.
Full offline gate remains unverified. safe_to_flash=false.
