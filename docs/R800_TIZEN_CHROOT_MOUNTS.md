# Tizen chroot fail-closed mount preparation

Baseline 00a90b13df969315613f543f38337d2d3819b94b: all seven
workflows passed; GPS host job 139764609327 in run 45777495314
confirmed all seven production restart loop fixture tests.

The previous setup could report chroot-ready after a failed mount.
Require command success and check exact unambiguous mount records,
read-only root, correct ext4 block source for p18/p16, tmpfs type
and writable mode, and matching device/inode for shared bind paths.
Verify lhd executable and firmware path readback. Reject conflicting
existing mounts, do not unmount or repair them automatically. A
failed attempt may leave partial mounts for manual review.
Charger mode now preserves the setup exit code and skips lhd on
failure, while continuing the charging UI. Android helper already
checks the exit code. Eleven new host fixtures use synthetic mount
records, real directory metadata, and a mock mount command that
always fails. No actual mounts, devices or firmware writes in tests.
Original BusyBox, kernel mount records and device behavior untested.
CI pending. safe_to_flash=false.
