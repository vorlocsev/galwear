# Explicit glibc probe in GNSS readiness

Baseline b9bfd1384913273b34ede8131ce6eb9ba66444c3 passed all seven
workflows. GNSS host job 139749193221 in run 45772799973 confirmed
all ten static donor gate tests.

Add --donor-qemu to a complete --tizen-image / --tizen-image-sha256 /
--donor-ndk / --donor-output invocation to request the existing isolated
unprivileged QEMU glibc probe. Supply only trusted original donor bytes.
The default still never executes donor code. No GNSS daemon is launched.
Validate the fresh report, the QEMU log digest, exact donor hashes,
ordered glibc/pthread/TLS/dlopen markers and non-release safety markers.
Only donor_glibc_qemu may pass from this evidence; Broadcom and hardware
remain untested. A failed probe is conservatively review-required.
Ten added synthetic tests pending exact-head CI. Original donor absent.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
