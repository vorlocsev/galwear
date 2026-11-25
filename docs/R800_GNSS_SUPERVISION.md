# GNSS daemon supervision (development candidate)

The Android helper now requires a successful, bounded tzchroot.sh invocation
before starting Tizen services. The GNSS stack has a single supervisor,
a 20-attempt budget, process-liveness checks and a 10-second retry delay.
The order is lhd, gpsd, gpsbridge; shutdown reverses the order. The sensor-only
path still starts lhd when the bridge is absent.

No network LTO download is performed. XTRA remains disabled by default.
The existing recursive ownership repair is retained because donor state
ownership is unresolved; it must be audited on a disposable donor image.
No new SELinux rules are introduced. The socket mode is now 0660;
actual GNSS UID/GID and SELinux label still require evidence. The tzchroot.sh payload itself is not available in this
repository snapshot.

Limitations: process liveness and delays do not establish protocol readiness;
foreground behavior of the donor daemons is assumed. TERM/KILL polling is bounded, but a child stuck in kernel I/O may remain alive. Restarting lhd can interrupt sensor clients.
Actual mount identity, socket access, readiness and restart behavior have
not been tested on a donor or watch. No release or flashing authorized.

safe_to_flash=false

Socket hardening: the daemon requires explicit verified R800_GPS_PEER_UID and
R800_GPS_PEER_GID at build time (default: daemon blocked). It creates a 0660
socket and checks the connecting UID with SO_PEERCRED. Existing paths are never unlinked without the ownership and liveness checks
below. Unmarked legacy sockets still require manual inspection. Parent directory trust and SELinux are unverified.
Shutdown now attempts TERM then KILL with bounded checks; if a child remains
alive, no new stack starts. Direct-child identity uses PPid, not pidfds.

## Exclusive socket ownership and recovery

The bridge now locks its owner-controlled parent directory with flock before
loading the donor library. statx confirms directory ownership and mode; on
ARM EABI the kernel syscall is 397, so the target must support statx (Linux
4.11+). After bind and final permissions, it records the socket inode, device
and ctime in a private owner marker. Recovery requires an exact marker match,
ECONNREFUSED on a nonblocking connect and unchanged identities before unlink.
Unmarked sockets, replaced files, symlinks, live listeners and incomplete
markers are blocked. A crash between bind and marker creation or between the
two unlinks requires manual review. Parent ancestors must remain trusted;
flock is cooperative and the pathname checks are not an atomic unlink CAS.
No UID/GID defaults or SELinux changes. Target statx/filesystem behavior and
full daemon integration are unverified.

Native Linux ownership fixture: PASS, GCC 14.2.0 with UBSan; exact Git blobs
for gps_ipc.h and test_r800_gps_ipc.c matched the locally tested sources.
ARMv7 softfp standalone header probe: ELF32 ARM EABI5 object compiled with
Clang; no target link or runtime test.
