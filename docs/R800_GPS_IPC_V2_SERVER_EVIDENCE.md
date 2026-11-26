# GPS IPC v2 server integration

Source reference: 89a16a29cff28f6dd03f85d167f8e0be649bb2c7.

The bridge now selects v2 only on an initial HELLO 2. Legacy START,
STOP, TIME and LOC select v1. No mode switch within a connection.
The server validates consecutive nonzero IDs, rejects duplicate and
out-of-order requests, and commits session state only after vendor
success. TIME/LOC remain connection-scoped, with the existing parsers.

The output mutex serializes ACK START with publication of the data ID.
Synchronous callbacks from START are intentionally dropped in v2
until ACK is sent. STOP disables v2 data before invoking the vendor
and emits ACK STOP only after success. v1 retains its callback path.
Invalid commands or short sends cause disconnect. No claim that a
wire ID identifies the originating proprietary vendor callback epoch.

Actual isolated host checks, 2026-11-26:
- d1e2ad7391031fbc13be836030639891b9d40e38 src/tools/gps/gps_server_v2.h
- 70ec0e222b56262721d8e73e5a6b81ffb5ad44be tests/test_r800_gps_server_v2.c
- 881fdee3ce6287203b59466733a48e8e2f66dff5 src/tools/gps/gps_protocol_v2.h

Local git hash-object matched all three. GCC -std=c11 -O2 -Wall -Wextra
-Werror -UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all:
server and client test executables both returned 0 under timeout 10s
and printed GPS_SERVER_V2=PASS and GPS_PROTOCOL_V2=PASS.
A freestanding Clang server probe compiled for armv7a-linux-gnueabi
-marm -mfloat-abi=softfp -mfpu=vfpv3-d16; readelf showed ELF32 ARM EABI5.
No complete bridge compilation, full regression or CI was performed.
git ls-remote failed to resolve github.com locally.

Two integration tests for ACK ordering and downgrade rejection were
added but not executed. The Android HAL still uses v1. Handshake/ACK
deadlines, actual post-ACK asynchronous DATA delivery and full
client integration remain outstanding. No target runtime verification.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
