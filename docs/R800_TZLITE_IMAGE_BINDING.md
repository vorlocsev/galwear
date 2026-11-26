# Static tzlite source image binding

Baseline da5d3ca4b847a87348e827c751d7406f990ea44f: all seven
workflows passed; GPS host job 139779613688, run 45782048563:
eight manifest readiness tests passed.

Use build/r800_tzlite_image_binding.py --root CANDIDATE --image
ROOTFS.img --image-sha256 IMAGE_DIGEST --manifest-sha256 MANIFEST_DIGEST.
Both digests must be recorded independently of the inspected files.
Verify candidate manifest and known component audit, copy the image
to a private verified snapshot, use read-only debugfs to audit the
same ELF closure including aliases, and compare the four explicit
regular configurations by size/hash. Require an exact set of
regular files and aliases (excluding the manifest), not an original
directory or permission layout. Recheck snapshot, input identity
and candidate inventory. No mounting, donor execution or reading
GNSS caches. Five additional tests use real compiled ARM32 ELF
and generated ext4 images, pending CI. This proves only matching
selected bytes to the supplied image digest, not Samsung authenticity,
ownership, runtime behavior, or deployment readiness. Original
Tizen image still unavailable. safe_to_flash=false.
