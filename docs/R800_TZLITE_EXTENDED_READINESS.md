# Extended static tzlite readiness

Baseline 7d31da4d7e64a9c536c0199658d6a4a322a8a562: 7/7 workflows
passed, GPS host run 45797593973 job 139833172046 confirmed four
real extended verifier cases and offline compile gate.

Use r800_gnss_readiness.py with --tzlite-extended-root,
--tzlite-extended-review-sha256, --tzlite-extended-stage-sha256
and existing --tizen-image and --tizen-image-sha256.
Independent optional tzlite_extended_binding gate; does not
replace baseline tzlite_manifest_integrity or tzlite_image_binding.
Require static tizen_image_closure pass, strict evidence bindings,
counts and explicit review items. Re-run full verifier at end
and revoke earlier static pass on mismatch. Missing inputs
NOT_TESTED. Baseline and extended paths must be distinct.
Eight new tests and strengthened real ext4 case pending CI.
STATIC_PASS is component match only; review items remain open.
Original donor and hardware unavailable. HOLD_RUNTIME_UNVERIFIED,
daemon_build_authorized=false, safe_to_flash=false.
