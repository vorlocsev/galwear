# PCM compat source audit (NON-RELEASE)

NDK ABI extraction passed on fc0260dfb3e9a3b5d5d87151411df94cd0afbe9d, run 45535631679.
Pinned Exynos base 50db73fc799f20a7120a8b5f653b16cc123d856f
sound/core/pcm_compat.c confirms APPL and AVAIL_MIN readback flags:
without them the handler overwrites runtime control fields. The
compat dispatch handles SYNC_PTR32, READI_FRAMES32, WRITEI_FRAMES32.
No patch paths touching these PCM/asound compat source files observed.

CI now downloads two exact source files and checks their Git blob
hashes, verifies source declarations and handler semantics, and compares
21 measured NDK values with the source-derived ARM32 layout. The
expected layout assumes 32-bit compat timespec and generic ARM ioctl
encoding. This is not a compiled kernel structure probe or runtime
compat verification. A mismatch fails the CI gate and records JSON.

Actual ABOX/DSP, kernel config/build and hardware playback remain open.
No release, no device writes. safe_to_flash=false.
