# Reported ext4 xattr inventory

Baseline 6d1254cb55666e479a05dfae22f524bf828bb243: seven workflows
passed. Host job 139791886001, run 45785725056: twelve inode
parser tests and real ext4 special-mode test passed.

Read ea_list by audited inode from the same private verified
snapshot. Cache per inode. Record only reported names, sizes and
categories: POSIX ACL, Linux capabilities, SELinux and other
security attributes. Do not log attribute values or restore them.
Reject malformed, duplicate, oversized listings or unexpected
diagnostics. NONE_REPORTED does not establish absence:
e2fsprogs dump_inode_attributes can return without an explicit
error when opening or reading attributes fails.
Reference: https://kernel.googlesource.com/pub/scm/fs/ext2/e2fsprogs/+/refs/tags/archive/debian/1.47.3_rc3-1/debugfs/xattrs.c

Ten parser tests and one real ext4 test with user and SELinux
attributes pending CI. ACL/capability categorization currently
tested by synthetic text, not real binary values. No effective
access or complete xattr verification. No original donor or
hardware. safe_to_flash=false.
