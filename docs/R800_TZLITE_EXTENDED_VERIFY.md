# Independent extended candidate verification

Baseline 523f934808afb23ee07fa3a82450b6375dd1c7aa: six successful
workflows, host integration run 45796788424 job 139829381976
confirmed all three extended staging tests and offline compile
gate; Android HAL passed, ARM QEMU job still running at review.

r800_tzlite_extended_verify.py --root CANDIDATE --image ROOTFS
--image-sha256 HASH --review-sha256 REVIEW_HASH --stage-sha256 STAGE_HASH

Recompute donor scope, plugin closure and extended review from
a fresh digest-verified snapshot. Require exact stage manifest,
tree, file set, normalized file modes, safe directory modes,
flattened aliases, excluded data and review items. Independently
audit staged ELF and four configs; recheck tree and manifest.
Four new real ext4 tests pending CI. Stage mode/ownership
verification is deliberately limited: original ownership, exact
ELF executable bits relative to donor, xattr values and deployed
access not verified. No runtime or authenticity claim. Readiness
integration deferred until this verifier passes CI. Stable isolated
inputs required. safe_to_flash=false.
