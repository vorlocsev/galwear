# Legacy scope in a raw ext4 image

Baseline 1b40472a0ebf3b0a9d0c9b68a2e75fcccd887c7c: 7/7 workflows;
GPS host run 45792898150 job 139816122941 confirmed nine
directory-based scope tests and offline compile gate.

Run python3 build/r800_tzlite_legacy_image_scope.py --image ROOTFS --sha256 HASH.
Verify a private raw ext4 snapshot and use read-only debugfs.
Inspect exact scope paths without following links; enumerate
three legacy trees with ls -p by inode and cross-check each
child inode with stat. Hash bounded regular files in temporary
private scratch, remove each immediately; do not stage or
execute files. Report missing paths, symlinks, hardlinks,
special objects and ELF magic candidates. Bound depth, inode
lookups, entries, directory sizes and total hashed bytes.
Directory listing output is bounded after capture. Long or
unusual symlinks, malformed listings and unsupported inode
formats require review. No authenticity, complete plugin or
runtime claim. Five parser and five actual ext4 tests pending
CI (local environment lacks debugfs). Original donor absent.
safe_to_flash=false.
