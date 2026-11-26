# GPS HAL epoch framing and reconnect evidence

Source reference: 8b0003096cd51258f6a67b9c0064d38ef60aed03.
Native isolated fixture: all three git hash-object values matched GitHub:
- af2b8ad140e510e9d7141d837429a9484cde5d25 src/hal/gps_epoch_frame.h
- cb3ca4134fae88657b8b9181b821d74583dbc59c src/tools/gps/gps_frame.h
- da8dc808d8e9ce402905e49a085577adf514cbe8 tests/test_r800_gps_epoch.c

GCC Debian 14.2.0-19, -std=c11 -O2 -Wall -Wextra -Werror
-UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all.
timeout 10s ./test-epoch returned zero and printed GPS_EPOCH_FRAME=PASS.
The test covers same-epoch fragmentation, changed epoch, repeated
epoch changes during discard, reset, NUL and oversized discarded frames.

A temporary translation unit using the same verified headers compiled
with Clang 17.0.0, armv7a-linux-gnueabi -marm -mfloat-abi=softfp
-mfpu=vfpv3-d16 -std=c11 -O2 -ffreestanding -Wall -Wextra -Werror.
readelf: ELF32, ARM, flags 0x5000000 Version5 EABI. Compile only.

HAL now tags each read batch with the locally observed session epoch,
discards cross-epoch partial lines within the existing framing limit,
checks socket health and replay START result, and resets frame and
satellite state on disconnect. The extended synthetic peer integration
scenarios were added but not run; the entire HAL was not compiled here.

Limitations: local epochs cannot identify complete old frames queued
before STOP/START if read after the transition; callbacks already
selected for dispatch can race a framework state change. Strict
end-to-end generation attribution would require an explicit protocol
boundary or session identifier. No full checkout, exact-head CI,
Android target ABI, donor, QEMU or hardware verification is claimed.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
