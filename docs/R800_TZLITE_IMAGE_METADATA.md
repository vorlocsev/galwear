# Original image inode metadata inventory

Baseline 5bd65b2ba5e16921a55b7530a8c0e26033e51b9c: all seven
workflows successful. Host job 139788058420, run 45784593851,
confirmed both ten-case tzlite readiness suites and actual
compiled ELF/ext4 readiness integration.

Read numeric UID/GID, mode, inode and hardlink count for selected
canonical audited files, parent directories and encountered image
symlink components, from the same hash-verified private snapshot
using read-only debugfs stat by inode. Fail closed on malformed
metadata. Flag special privilege bits, group/other writable paths
and multiple file hardlinks for review, separately from byte match.
Do not restore owners or modes, do not infer effective access,
ACLs, capabilities or xattrs. No original ownership verified claim.
Nine parser tests plus one real ext4 case (distinct numeric owners,
setuid flag stripped in staged file) pending CI. The sole write
debugfs operation is on the disposable synthetic fixture in tests.
Original donor absent. safe_to_flash=false.
