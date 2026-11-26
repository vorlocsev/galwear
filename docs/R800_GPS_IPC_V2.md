# GPS IPC v2 contract (development, not deployed)

Current transport remains v1. The shared v2 header defines negotiation
literals HELLO 2 / READY 2, START id, STOP id, ACK START id, ACK STOP id,
and DATA id followed by FIX, NMEA or STATUS payload. The parser accepts
complete bounded lines without newline; payload validation belongs to
existing wire parsers. Negotiation literals are not parsed by the message
parser. TIME/LOC, handshake deadline and server state are pending.

IDs are connection-local, strictly increasing nonzero uint32 values,
without wrap. Client accepts data only after matching START ACK and
before STOP request. Future IDs and unexpected ACKs require disconnect;
old data is dropped. On reconnect reset protocol state. The server
must serialize ACK and data, suppress or buffer synchronous START
callbacks until ACK, and avoid labeling old queued events with new IDs.
Failure of a vendor operation or write requires disconnect. A wire ID
does not establish the originating proprietary callback generation.

## Actual local evidence 2026-11-26

Exact git blob matches:
- 881fdee3ce6287203b59466733a48e8e2f66dff5 src/tools/gps/gps_protocol_v2.h
- 6ccd75036af7f351fe29cd0af714a573488ad228 tests/test_r800_gps_protocol.c

GCC Debian 14.2.0-19, -std=c11 -O2 -Wall -Wextra -Werror -UNDEBUG
-fsanitize=undefined -fno-sanitize-recover=all: timeout 10s test returned
zero, GPS_PROTOCOL_V2=PASS. Includes 17 rejected input strings plus
valid syntax, acknowledgement ordering, stale and future data, and ID
exhaustion. The required core suite now includes protocol.
Clang 17.0.0 compiled a temporary freestanding probe calling parse,
receive and request for armv7a-linux-gnueabi -marm -mfloat-abi=softfp
-mfpu=vfpv3-d16; readelf ELF32 ARM Version5 EABI (0x5000000).

No endpoints changed, no complete core suite, full checkout, CI,
actual ARM execution or hardware test. No deployment authorization.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
