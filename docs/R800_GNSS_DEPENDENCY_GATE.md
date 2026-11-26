# GNSS dependency review gate

Baseline d77f2273b53479a5eaf4914c4f4c5eb37bf36228: 7/7 workflows
passed. GPS run 45770504196 confirmed all ten donor pipeline cases,
including real ext4 rejection paths and simulated link/QEMU evidence.

The generic Tizen dependency auditor intentionally reports symbol
and relocation uncertainty separately from file closure. GNSS
preflight now propagates that uncertainty into review-required:
non-EABI5/hard-float objects, incomplete dynamic symbol inventories
or target scopes, strong unresolved or ambiguous candidate imports,
relocation review, and exhausted symbol budget. Weak missing imports
remain visible without implying definite failure. The complete
bounded closure evidence, hashes, aliases and edges are retained
in the report. No changes to generic Tizen auditor semantics.

Seven new GNSS cases and required dedicated GNSS/dependency suites
are pending exact-head CI. Original Tizen input not available;
no actual Broadcom ABI or runtime acceptance. safe_to_flash=false.
