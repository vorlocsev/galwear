# Static original/staged permission differences

Baseline 65d8cba6e13d31dcee5cfb8c5cdf8414b42b77d8: seven workflows
passed; GPS host run 45789505166 job 139804643339 confirmed 11
DAC tests and actual ext4 detour test.

Inspect staged UID/GID, modes and xattr names (not values) without
following symlinks. Bind kind/mode/link text to existing manifest;
recheck metadata after audit. Compare original and staged inode
metadata and conditional read/execute/search candidates for
canonical and flattened alias paths. Include staged root directory
mode: private 0700 can deny a different nonroot location UID.
Original-only or staged-only paths are structural differences,
not instructions to copy or restore them. Host staging ownership
does not represent deployed ownership. Staged ACLs require review.
Never apply chown, chmod or xattrs; no effective access claim.
Seven unit tests and strengthened ext4 special-mode case pending
CI. Stable isolated input required. Original donor absent.
safe_to_flash=false.
