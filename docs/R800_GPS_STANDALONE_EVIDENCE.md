# Standalone GPS lifecycle regression

Source reference: 0f13d3d65e8fce0a6c33258564e3fe7a5b9aa178.

Actual local verification on 2026-11-26: two files reproduced in an
isolated fixture, git hash-object matched the GitHub blobs:
- 809e33c2564517157e732e73fbec93ad6db33e1a src/tools/gps/gps_standalone.h
- 9761b83c738d8c305077ae1992ef095f6460e03c tests/test_r800_gps_standalone.c

GCC 14.2.0, -std=c11 -O2 -Wall -Wextra -Werror -UNDEBUG
-fsanitize=undefined -fno-sanitize-recover=all. Native test under
timeout 10s returned zero and emitted GPS_STANDALONE_GATE=PASS.
Six lifecycle sequences, two accepted durations and ten rejected
arguments were asserted within one executable. This is a synthetic
function-table test, not the complete bridge, donor ABI or hardware.

The standalone main now rejects invalid arguments before locking or
loading the vendor library, propagates configuration/start/stop failures,
and cleans up after normal stop or failed configuration. Following a
failed start or stop it exits without additional vendor calls because
the engine state is unknown. The initial init failure remains a
nonzero process exit. Duration is deliberately bounded to 1..3600
seconds (default 90). Daemon lifecycle policy remains unchanged.

The modified complete bridge and complete offline suite were not
compiled or executed in this step. No CI, QEMU, target link, original
donor or physical verification is claimed.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
