# R800 Audio HAL candidate (NON-RELEASE)

Original tools/audio/tinyalsa-2.0.0-sync-ptr.patch is absent from the
active source tree. This is a reconstructed minimal candidate against
tinyalsa commit 1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d, not a recovered
original. pcm_generic_transfer calls pcm_state before read/write;
pcm_state invokes pcm_sync_ptr(pcm, 0). With ioctl-backed status the
zero flags write the userspace shadow application pointer back to the
kernel. For non-mmap PCM only, request APPL and AVAIL_MIN readback;
preserve existing mmap commit semantics. No kernel ABI layout changes.

Compile the candidate in a fresh archive of the pinned source, use
a host mock for the actual patched function, statically link tinyalsa
into audio.primary.r800.so, check ELF and HMI, retain JSON only.
The existing audio_linked / patched_tinyalsa_linked flags remain false
for the original hardware-validated path; separate candidate evidence
is recorded. Actual compat ioctl behavior, ABOX and HFP routing,
hardware playback/capture, original patch equivalence not established.
No binaries published, no hardware test. safe_to_flash=false.
