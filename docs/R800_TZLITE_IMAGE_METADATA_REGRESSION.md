# Metadata parser regression

7e8b1a77f5d08012b3cdbf493191b1893a0c8579: 4/7 workflows passed.
GPS host job 139790061034 in run 45785188352 failed in
test_original_metadata_not_restored with unrecognized inode metadata.
11 other compiled ELF/ext4 cases passed; Android HAL and ARM QEMU
jobs passed. The parser incorrectly rejected five-digit octal
permissions. e2fsprogs internal_dump_inode formats permissions with
a literal leading zero and at least three octal digits, masking
with 07777, so setuid 4755 is printed 04755.
Reference: https://browse.dgit.debian.org/e2fsprogs.git/tree/debugfs/debugfs.c?h=debian/1.47.1_rc1-3&id=8cfc832cf6771c950c9220b6fe8c9df82f577c52

Accept exactly the valid padded/unpadded forms and reject file
type bits or multiline mode fields. Use the actual padded
special-mode format in the unit fixture and retain the real ext4
special-mode test. Include guest path on parse errors without raw
attribute contents. Three additional test methods. CI pending.
No original donor or device changes. Extended attribute audit
deferred pending green CI. safe_to_flash=false.
