# GNSS shared IPC startup metadata

Baseline 94cacdebd0050776f50a2c697bac46ad29995843 passed all seven
workflows. GPS host job 139758743222 in run 45775704533 passed
11 policy readiness tests and real synthetic SELinux integration.

The existing helper starts lhd, waits 20 seconds, starts gpsd,
waits five seconds, then starts the bridge. These delays remain
heuristics, not hardware readiness. Before gpsd and again before
the bridge, require matching device/inode and root ownership of
the Android/Tizen IPC directory, no final-component symlink,
and no group/world write permission. On mismatch the GNSS workers
are not started in that attempt. Existing sensor-only lhd path
and restart limits remain unchanged.

While all three workers survive, report changes in socket/marker
metadata: identical device/inode, expected uid, modes 0660/0600,
single links and 40-byte marker. No connection or marker-content
read. Even a bound non-listening socket may satisfy this heuristic;
no runtime or SELinux verification is implied. No socket removal
or chmod by the new observer. The existing bridge owns recovery.
Eleven real host filesystem/shell fixture tests pending exact-head CI.
Original BusyBox and watch mounts not tested. safe_to_flash=false.
