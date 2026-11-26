# GPS daemon signal shutdown evidence

Source reference: 82d6757640e5a8f462bb72af0d6ce26b93bb4e0d.

Actual local checks on 2026-11-26: git hash-object matched the two
published source blobs:
- a15c4d95c54da831247a678c0269440d55d002a2 src/tools/gps/gps_shutdown.h
- dbd90a956f108b5c1ef4aef1ea54d1c189aba641 tests/test_r800_gps_shutdown.c

GCC Debian 14.2.0-19, -std=gnu11 -O2 -Wall -Wextra -Werror
-UNDEBUG -pthread -fsanitize=undefined -fno-sanitize-recover=all.
Five invocations under timeout 5s all returned zero and emitted
GPS_SHUTDOWN_GATE=PASS. SIGTERM was raised by a separate pthread
while the owner waited on a pipe; a readable pipe was checked first.

A temporary freestanding translation unit including the exact header
compiled using clang --target=armv7a-linux-gnueabi -marm
-mfloat-abi=softfp -mfpu=vfpv3-d16 -std=c11 -ffreestanding.
readelf: ELF32, ARM, EABI5. Undefined symbols: signal, poll,
__errno_location only. No target execution or linking.

The main daemon now polls listener/client sockets, uses nonblocking
accept/recv semantics, requests shutdown via a lock-free atomic flag,
and invokes existing lifecycle close and verified socket recovery.
The 200 ms timeout bounds idle poll waits, NOT vendor calls, fsync,
cleanup or total process termination time. Vendor signal handler
replacement, blocked signals and callback thread quiescence remain
unverified. Two integration tests for SIGTERM during idle and active
sessions were added but not executed. The complete bridge was not
compiled during this step. Local git ls-remote failed to resolve
github.com. No CI, original donor, QEMU or hardware claim.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
