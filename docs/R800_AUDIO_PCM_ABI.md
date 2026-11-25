# R800 Audio PCM ABI evidence (NON-RELEASE)

Exact-head baseline 2edca42c947a3cb9fff792a500c372971ac44267, run 45535460999: all five HAL objects
compiled and linked, candidate SYNC_PTR mock passed. Original audio
patch equivalence and actual sound output remain unverified.

Record ARM32 NDK PCM sizes, offsets, ioctl numbers and flag values
directly from a compiled data section (no execution, no device).
Check Audio SONAME, NDK dependency allowlist, no custom search paths
or text relocations. Report v4 distinguishes five successful links
from hardware acceptance; original Audio compatibility flags stay false.

Next: compare this measured NDK layout with the pinned Exynos kernel
compat ioctl structures and verify actual PCM transfer/ABOX behavior.
No kernel compat claim from NDK alone. No binaries uploaded.
safe_to_flash=false.
