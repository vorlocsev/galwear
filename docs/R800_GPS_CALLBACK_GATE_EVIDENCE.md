# GNSS callback delivery phase gate

Source reference: 2ece26df6da5051e52a32e5ef7e3a5b97dc04198.

Actual local checks on 2026-11-26: two files reconstructed and verified
against GitHub using git hash-object:

- f0e7e30efbe3882645a76d4150641e3277851326 src/tools/gps/gps_callback_gate.h
- 64b47af3ee9a403a055d7a7d5042ab7d359a3482 tests/test_r800_gps_callback.c

GCC Debian 14.2.0-19, -std=c11 -O2 -Wall -Wextra -Werror
-UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all -pthread.
Native executable under timeout 10s returned zero and emitted
GPS_CALLBACK_GATE=PASS. Eight assertions cover data and status
permission in CLOSED, ACTIVE, STOPPING and an unknown phase.

A temporary probe translation unit including the exact header compiled
with Clang 17 for armv7a-linux-gnueabi -marm -mfloat-abi=softfp
-mfpu=vfpv3-d16 -std=c11 -ffreestanding -Wall -Wextra -Werror.
readelf: ELF32, ARM, EABI5. Compile only.

GPS Bridge wraps location, NMEA and status callbacks with a dedicated
mutex and phase gate. START opens the gate before the vendor call
to accommodate synchronous callbacks. STOP blocks data before invoking
the vendor but permits status until it returns. Failure and cleanup
close all three callback types. Vendor calls are outside the gate mutex.
The new mock integration test asserts late data suppression during STOP,
idle TIME injection and the next START; it was added but not executed.
The mutex integration and full bridge build were not tested locally.

This phase gate does not identify the originating vendor session of a
callback delivered after a new START, prove vendor worker termination,
or revoke callbacks already emitted before a transition. The Android
HAL reconnect implementation is unchanged. No complete checkout, CI,
original donor, QEMU or physical GNSS verification is claimed.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
