# R800 exact-path preflight and heartbeat regression alignment
Head 1d2f0d4ac21bf0b7da31a6f2821a68192603b15c: kernel source preflight rejected new arch/arm64/kernel/smp.c
because arch was outside the allowlist. Admit only that exact path;
retain rejection of other arch paths and path traversal. Existing
read-only init now emits numbered heartbeats after successful nanosleep,
so update stale static assertion to match that behavior. Install DTC
in the second integrated validation workflow too.
No boot success claims for patched virt kernel; rerun exact-head CI.
safe_to_flash=false.
