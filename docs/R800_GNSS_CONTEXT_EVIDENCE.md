# GNSS IPC compatibility and SELinux context evidence

Baseline 7159f9453f3b401a2a0d5cbde80debb27fd89cd0: four of seven
workflows succeeded. GPS run 45773795593 host job 139752468956
passed 19 integration and 16 registration tests, then failed importing
SERVICE from the IPC module. Android NDK and synthetic ARM QEMU
jobs succeeded. Restore the existing public SERVICE alias while
keeping shared AOSP/Samsung service selection.

Add literal context candidates with file hashes and line numbers.
Check identification and conflicting exact hwservice labels for IGnss
and Samsung ISecGnss when applicable. File-context PCRE, precedence,
type transitions, compiled contexts and actual SELinux allow rules
are not evaluated. Missing exact names require review, not policy
modification. Seven additional synthetic IPC/context tests pending CI.
No permissive mode, no policy change, no hardware claim.
safe_to_flash=false.
