# Extended static candidate staging

Baseline f995ed3a1ccca59e7d9154d6e987af05d17596c6: 7/7 workflows;
GPS host run 45796019746 job 139826734098 confirmed seven manifest
tests and extra compiled ARM ELF case.

First run r800_tzlite_legacy_image_scope.py --image ROOTFS --sha256 HASH
--extended-manifest; record extended_manifest_sha256 even when
scope review items remain. Then run r800_stage_tzlite_extended.py
--image ROOTFS --image-sha256 HASH --review-sha256 REVIEW_HASH
--output NEW_DIRECTORY as an unprivileged user. Recompute evidence
from same private verified snapshot and require exact digest.
Stage only AUDITED_ELF and all four KNOWN_CONFIG paths, not
UNREVIEWED_DATA, and create only required directories and audited
flattened ELF aliases. Re-audit ELF closure and config hashes,
verify output tree, normalized permissions, atomic no-replace
publish. Separate extended-stage schema deliberately rejected by
existing baseline manifest verifier. No original privileges or
runtime authorization; review items remain unresolved. Three new
real ext4 cases pending CI. Original donor unavailable.
safe_to_flash=false.
