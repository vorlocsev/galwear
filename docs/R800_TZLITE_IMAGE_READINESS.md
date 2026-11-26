# tzlite source image readiness gate

Baseline f29a575d82b1ce90d6a049daa36140725cd85fd9: all seven
workflows successful. Host job 139782480417, run 45782917189,
confirmed ten real compiled ARM32 ELF/ext4 staging tests.

Provide --tzlite-root, --tzlite-manifest-sha256, --tizen-image
and --tizen-image-sha256 to GNSS readiness. The new
tzlite_image_binding gate requires successful manifest integrity,
known component and GNSS image closure checks before launching
the independent image binding auditor. Bind both external hashes,
schema, snapshot flag, four config records, nonnegative counts
and explicit false runtime/authenticity/ownership claims.
If final manifest recheck fails, revoke the binding pass.
Missing inputs are NOT_TESTED. Nine gate fixture tests plus one
compiled ELF/ext4 actual subprocess integration case pending CI.
Comparison is selected byte provenance to the supplied digest,
not official firmware authentication. Stable offline inputs
required; no real donor supplied, no hardware or flash changes.
HOLD_RUNTIME_UNVERIFIED. safe_to_flash=false.
