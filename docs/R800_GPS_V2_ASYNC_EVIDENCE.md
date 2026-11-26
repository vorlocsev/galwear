# IPC v2 asynchronous mock integration

Source reference: 5e47113eef6666779f3256551ba9a744ed4aa578.

The test-only async-data mock creates a joinable worker through the
bridge's create_thread_cb. A valid LOC request while active triggers one
FIX/NMEA pair on the worker. This gives the integration client an explicit
post-ACK trigger rather than relying on a scheduling delay. STOP and cleanup
cancel or join the worker before returning. Existing normal mock behavior
is retained, including synchronous START callbacks.

Actual native verification on 2026-11-26: four local git hash-object values
matched the published blobs:
- 4fd5f7d01e942711549daa23d8cd63995f549dda src/tools/gps/gps_abi.h
- b4d3b3101a2d0e8dc7f7be7f1b068bac06181de0 tests/r800_mock_async.h
- ebd813059bc71011aa6571360de5360e06c00e0f tests/test_r800_gps_mock_async.c
- 6d3c999da1bb8efdee9e60b775a8026295146489 tests/r800_mock_brcm.c

GCC -std=c11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread
-fsanitize=undefined -fno-sanitize-recover=all: five runs of the isolated
worker test under timeout 5s returned zero and printed GPS_MOCK_ASYNC=PASS.
The test covers cancellation, duplicate worker rejection, delivery on a
different pthread, restart, and missing/failed thread creation.
The exact updated mock also compiled as a native shared object with
-std=gnu11 -fPIC -shared and the same warning/sanitizer flags.
readelf confirmed GLOBAL DEFAULT FUNC gps_get_hardware_interface.

Added two integration scenarios: actual host HAL and bridge v2 with
two sessions, and raw v2 socket peer reconnect with tagged asynchronous
data. They are registered in the existing integration suite. The complete
bridge and HAL sources were not built or run during this step: local
git ls-remote failed DNS resolution for github.com. The new integration
scenarios remain NOT TESTED. No CI, Android ABI, original Broadcom,
QEMU or physical GNSS evidence. V1 remains default; v2 opt-in only.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
