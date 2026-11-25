# GNSS daemon supervision (development candidate)

The Android helper now requires a successful, bounded tzchroot.sh invocation
before starting Tizen services. The GNSS stack has a single supervisor,
a 20-attempt budget, process-liveness checks and a 10-second retry delay.
The order is lhd, gpsd, gpsbridge; shutdown reverses the order. The sensor-only
path still starts lhd when the bridge is absent.

No network LTO download is performed. XTRA remains disabled by default.
The existing recursive ownership repair is retained because donor state
ownership is unresolved; it must be audited on a disposable donor image.
No new SELinux rules or socket permissions are introduced. The original
0666 socket mode remains a blocker until the actual GNSS UID/GID and label
are verified. The tzchroot.sh payload itself is not available in this
repository snapshot.

Limitations: process liveness and delays do not establish protocol readiness;
foreground behavior of the donor daemons is assumed. TERM and wait may block
if a child refuses to exit. Restarting lhd can interrupt sensor clients.
Actual mount identity, socket access, readiness and restart behavior have
not been tested on a donor or watch. No release or flashing authorized.

safe_to_flash=false
