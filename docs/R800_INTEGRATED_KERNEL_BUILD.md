# R800 integrated kernel build (NON-RELEASE)

Base 022680834dff6f19242b0ca92d097b8b26bcaded: six exact-head workflows passed, including ABOX source
apply check and five HAL links. Enable existing kernel Image smoke
workflow on the display/audio development branch, restricted to the
existing path filters. Verify checkout SHA and effective config,
require ABOX and PCM object files in addition to Image, record hashes
of input patch/config and compiled outputs. No initramfs, no binary
artifacts, no donor images or device contact.

The full kernel build is a separate gate, not inferred from source
preflight. Existing pinned Alpine LLVM toolchain and full-source
checkout may still fail. Successful Image would not prove boot,
runtime PCM compatibility or safe flash. safe_to_flash=false.
