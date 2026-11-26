# GPS daemon lifecycle state gate

Source reference: 145203ec3a463215c5586ae39abae10e64f47c9b.
Actual local isolated host test, 2026-11-26:
- 3848eed3029e8141ff3802aba25c7565693c073c src/tools/gps/gps_daemon.h
- a5d568fba6348352528cfbf5010023748c4d7028 tests/test_r800_gps_daemon.c

Both git hash-object outputs matched the published GitHub blobs.
GCC Debian 14.2.0-19, -std=c11 -O2 -Wall -Wextra -Werror
-UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all.
timeout 10s ./test-daemon returned zero, GPS_DAEMON_GATE=PASS.
Eight synthetic lifecycle scenarios were asserted inside one executable.

The daemon now permits one reinit after configuration failure before
START. START or STOP failure transitions to BROKEN, disallowing further
vendor operations. Closing a READY or successfully stopped ACTIVE
state invokes cleanup once. This deliberately removes the old retry
after failed START, which might leave the proprietary engine active.
Cleanup is void; neither successful cleanup nor vendor thread shutdown
can be independently established by this state machine.

The mock and integration suite were updated to reflect the changed
failure policy, but the full bridge, mock integration, ARM target
link and complete checkout were not compiled or executed in this step.
getent hosts github.com returned no addresses. No CI or hardware claim.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
