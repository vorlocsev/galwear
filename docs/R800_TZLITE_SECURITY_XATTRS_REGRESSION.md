# Binary ACL extraction regression

fc2d8af03ae4e527973748fd7aca4f13249840c1: 4/7 workflows.
GPS host run 45787282952, job 139797150488 failed in
test_binary_security_attributes_not_restored with Attribute
extraction size mismatch. Other 13 compiled ELF/ext4 cases,
Android GPS HAL and ARM QEMU jobs passed.

debugfs ea_list uses ext2fs_xattrs_iterate, exposing the stored
attribute length. ea_get normally converts disk ACL to Linux
POSIX ACL xattr format, expanding short entries and changing
length. It also changes unnamed-entry ID representation across
versions. Use ea_get -r -f, compare actual raw length exactly,
parse disk ACL version 1 with short and named entries, normalize
in memory to existing validated POSIX parser. Hash raw bytes.
Capabilities remain unchanged raw VFS structures.
Source: https://kernel.googlesource.com/pub/scm/fs/ext2/e2fsprogs/+/refs/heads/master/lib/ext2fs/ext_attr.c
Source: https://kernel.googlesource.com/pub/scm/fs/ext2/e2fsprogs/+/refs/tags/archive/debian/1.47.3_rc3-1/debugfs/xattrs.c

Four new parser tests and strengthened existing ext4 roundtrip.
No relaxation of length or security checks. CI pending.
No donor or device changes; effective DAC calculation deferred
until green CI. safe_to_flash=false.
