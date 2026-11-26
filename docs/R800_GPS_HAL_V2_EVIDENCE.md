# HAL IPC v2 integration

Source reference: e89844aac09a5cdc078c6c56742155329dc2179e.

The Android HAL supports an explicit opt-in R800_GPS_IPC_V2=1.
Default remains v1. The reader owns the v2 state machine, sends HELLO,
checks READY and command ACK deadlines using CLOCK_MONOTONIC (5 s),
and reconciles desired state every 100 ms while polling. No downgrade.
TIME/LOC are blocked until READY. ACK START/STOP produce logical
session notifications; vendor session begin/end DATA are suppressed.
A disconnect ends the announced session, resets the stream and
satellite state, and retains the wanted state for the next connection.
Rapid STOP/START is reconciled by the epoch and serialized requests.

Actual local checks, 2026-11-26: GCC Debian 14.2.0-19 with -std=c11
-O2 -Wall -Wextra -Werror -UNDEBUG -fsanitize=undefined
-fno-sanitize-recover=all. All three executables returned zero:
GPS_PROTOCOL_V2=PASS, GPS_SERVER_V2=PASS, GPS_V2_CONTROL=PASS.
Verified exact local blobs against published files:
- 881fdee3ce6287203b59466733a48e8e2f66dff5 gps_protocol_v2.h
- d1e2ad7391031fbc13be836030639891b9d40e38 gps_server_v2.h
- e70eb407fc701074bb2187538eb03760a7b65f0c gps_v2_control.h
- 6ccd75036af7f351fe29cd0af714a573488ad228 test_r800_gps_protocol.c
- 70ec0e222b56262721d8e73e5a6b81ffb5ad44be test_r800_gps_server_v2.c
- 6d78a3390ae6816e2b997c057420323ed98eb76a test_r800_gps_v2_control.c

Temporary freestanding controller probe compiled with Clang for
armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16
-std=c11 -O2 -ffreestanding -Wall -Wextra -Werror. readelf confirmed
ELF32 ARM Version5 EABI. Compile only.

Added native synthetic-peer test to the required full offline suite.
The complete HAL, bridge and new peer test were not built or run
in this step: local git ls-remote failed DNS resolution of github.com.
The controller tests are not endpoint integration evidence.
No full CI, NDK binary ABI, QEMU, proprietary callbacks or device tests.
The opt-in mode is not a deployment authorization. Callback dispatch
can still race framework changes; wire IDs do not establish the
proprietary callback's originating session.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
