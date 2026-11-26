# Legacy scope inventory, offline prepared donor tree

Baseline 4de6058e95e987582963c0e08d5cefa94548d8c5: 7/7 workflows;
GPS host run 45792230841 job 139813864140 confirmed eight review
plan tests and offline compile gate.

Run python3 build/r800_tzlite_legacy_scope.py --root PREPARED_ROOT
on an isolated stable prepared root, not the host /. Inspect the
14 legacy FILES plus gconv cache, three recursive TREES and six
top-level LINKS. Report SHA-256 and ELF magic candidates, not file
contents. Never traverse symlinks, open special files, copy or
execute. Missing paths, symlink or hardlink review and special
objects are explicit. Bound entries, depth and regular file bytes,
recheck observed inode metadata. AST parity test keeps the list
aligned with the legacy copier without importing that copier.
Nine fixture tests pending CI. This is a directory-based scope
audit only; raw ext4 directory enumeration deferred. Symlink
targets, additional dependencies, configuration semantics,
original donor authenticity and effective runtime remain unverified.
Assumes stable isolated source (not resistant to hostile concurrent
parent replacement). No original donor or device. safe_to_flash=false.
