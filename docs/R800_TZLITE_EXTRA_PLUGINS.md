# Discovered sensor plugin dependency audit

Baseline 29bf3913a15431f868d4d521ae83e392d11fdeb7: 7/7 workflows.
GPS host run 45793776933 job 139819100281 confirmed all ten
legacy ext4 inventory tests.

Opt-in --audit-plugins on r800_tzlite_legacy_image_scope.py
runs a combined static closure for known tzlite targets and
up to 64 additional regular ELF candidates under /usr/lib/sensor.
Use the same private snapshot and bounded ImageResolver.
Bind each discovered candidate to the inventory path, length
and SHA-256; inspect ELF type, dynamic inventory, ARM ABI,
DT_NEEDED, version/symbol scope and relocations. Preserve all
inventory review reasons, including symlink and hardlink scope.
An empty candidate list is not plugin completeness. Per-target
candidate status is not a whole-closure pass. Static symbol
scope may not include caller exports and does not verify dlopen.
No files are staged or executed. Three real ext4/ARM ELF cases
added to mandatory host suite, CI pending. No original donor.
safe_to_flash=false.
