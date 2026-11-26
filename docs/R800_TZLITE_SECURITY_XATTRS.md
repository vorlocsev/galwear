# Selected binary security xattrs

Baseline 40aa08823fe23a0d804e7646a87ce9570a10a841: seven workflows
passed. Host job 139794915710, run 45786631247: ten name parser
tests and real xattr inventory test passed.

Read only reported POSIX ACL access/default and file capabilities
using ea_get -f by inode into private scratch, check lengths and
diagnostics, unlink temporary values. Default (non-raw) libext2fs
converts disk ACL to Linux POSIX xattr version 2:
https://kernel.googlesource.com/pub/scm/fs/ext2/e2fsprogs/+/refs/heads/master/lib/ext2fs/ext_attr.c
Parse tags, permissions, ID ordering, singleton/mask rules and
compare ACL classes with inode mode. Parse VFS capability versions
1/2/3, flags and sizes; report aggregate bit counts and hashes,
not raw bytes or named IDs. No runtime privilege inference.
Ten structural fixture tests and one actual ext4 binary attribute
test pending CI. Test writes only disposable image. No original
donor, no attribute restoration. safe_to_flash=false.
