# Synthetic binary policy integration

Baseline 73458f9fdae231d2a41bf0fe932eee1c0ab557f6: seven workflows
successful; GNSS host job 139756215798 in run 45774937885 passed all
ten mocked SETools tests.

Add a mandatory host CI step installing secilc and SETools from the
Ubuntu package repositories. Generate a small CIL policy, compile
it into a real binary, and inspect it with actual seinfo/sesearch.
Seven cases cover AOSP/Samsung, source attribute membership,
missing and conditional connectto, missing Samsung registration,
unknown type and wrong digest. No policy is loaded into the kernel.
Exact-head metadata acceptance now requires the real-tool step.

The unconditional and conditional CIL variants were compiled locally
using libsepol CIL APIs; actual SETools execution is pending CI.
No original Android policy or effective runtime labels were supplied.
safe_to_flash=false.
