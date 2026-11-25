# R800 ABOX firmware request hardening (NON-RELEASE)

Base 5616078bd53270eac6ad0cd26b16a484cd1c8552; 6/6 workflows passed. The pinned kernel async firmware
callback retries missing SRAM firmware, but immediate request submission
errors were ignored. Serialize SRAM request submission with an atomic
in-flight flag and count scheduled automatic retry attempts atomically.
Keep 60 automatic retries at 2-second spacing. Reject invalid image
sizes and bootargs range before copying SRAM/DRAM. Do not change
the existing opt-in DSP poweroff policy or firmware contents.

CI checks the ABOX hunk against a blob-hash-verified pinned kernel file.
No full kernel compile or real DSP test. Existing global delayed work
and asynchronous callback lifetime across driver unbind/remove still
require separate correction. DRAM/extra firmware missing after successful
SRAM, and repeated explicit enable requests after retry exhaustion,
remain unresolved. No guarantees of hardware recovery. safe_to_flash=false.
