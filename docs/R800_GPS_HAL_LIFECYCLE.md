# R800 Android GPS HAL lifecycle

The reader owns the socket and callback delivery. State changes and shutdown
are protected by one mutex; reconnect waits can be interrupted by cleanup.
The framework callback table is copied by complete fields. Legacy callback
tables remain supported; a second init while a reader is alive returns EBUSY.
The callback-created thread may be detached, so cleanup waits for reader
quiescence rather than assuming pthread_join is supported.

START/STOP track desired state; START is replayed after reconnect.
Session status now comes from the bridge rather than optimistic local events.
Location/NMEA are suppressed when no session is requested. A callback already
in flight may finish while stop runs; ordinary cleanup waits for the reader.
Self-cleanup requests stop but cannot wait on the calling reader.

Nonblocking connect rejects an unavailable or saturated Unix socket and retries.
No real GNSS, vendor callback ABI or module unload timing has been verified.
The HAL remains a singleton. A framework that does not eventually launch
a successfully returned callback thread violates the assumed thread contract.
Satellite GSV/GSA validation is a separate follow-up.

safe_to_flash=false

## Synthetic bridge integration

The host peer fixture checks outgoing START/STOP/TIME/LOC, fragmented FIX,
NMEA checksums, GPS/SBAS reports, incomplete GSV, session epoch resets,
reconnect and malformed-frame shutdown. It drives the actual Android HAL
reader via a temporary local socket. The Tizen bridge and donor libraries
are not executed. No wire session acknowledgement or generation ID exists;
frames already in flight cannot be attributed unambiguously to a session.
