# Android 11 ARM64 runtime from AOSP (non-release)

This is a **generic QEMU virt dependency**, not an SM-R800 Wear OS image.
No proprietary GSI donor, Google services, vendor binaries or flashable
firmware are needed for this source-build experiment.

Pinned AOSP release: android-11.0.0_r48 (RD2A.211001.002).
Manifest commit: 4466d48178452bf5ac136852bf2768af407a0584.
Manifest: https://android.googlesource.com/platform/manifest/+/refs/tags/android-11.0.0_r48

Use a dedicated compatible Linux x86_64 build host with the AOSP host
dependencies installed, a supported repo launcher, Python 3, Git, readelf,
debugfs and enough RAM/disk for a full source checkout and Soong build.
Do not assume a standard GitHub-hosted runner has sufficient disk space.
Consult https://source.android.com/docs/setup for host setup; Android 11
may require an older compatible build distribution/toolchain.

Prepare a fresh AOSP source directory (not the GalWearOS repository):

    mkdir aosp-r48
    cd aosp-r48
    repo init -u https://android.googlesource.com/platform/manifest -b android-11.0.0_r48
    repo sync -c -d -j4

Then from the GalWearOS checkout:

    bash build/r800_aosp_runtime_build.sh /absolute/aosp-r48 /absolute/new-runtime-evidence 4

The script requires the pinned manifest commit, rejects local manifests and
dirty or mismatched project heads, captures the resolved manifest, selects
aosp_arm64-eng and requests only the com.android.runtime target. It checks
the expected unflattened system/apex/com.android.runtime.apex output. It
runs the existing read-only extractor to stage linker64, libc.so, libdl.so,
libm.so and the linker alias. Keep all AOSP output local; only evidence files
are candidates for review.

If the build produces a flattened APEX, a different layout, or additional
runtime dependencies, the script stops rather than choosing a different
binary or pretending that the NDK stub libraries are the runtime.

After compiling the dynamic API 30 probe with the pinned NDK, inspect it
against the extracted runtime:

    python3 build/r800_android_dynamic_audit.py --probe /absolute/probe \
      --runtime-root /absolute/new-runtime-evidence/runtime-root \
      --report /absolute/dynamic-runtime-evidence.json

Remaining: linker configuration, additional runtime dependencies as actually
observed, a temporary guest archive, boot and execution in QEMU, and log
validation. This recipe is not a verified build or bit-reproducibility
guarantee. No APEX signature verification, actual watch test or Wear OS
framework boot has occurred. safe_to_flash=false.
