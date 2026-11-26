# Cache rebuild review plan

Baseline 04d6dd93ef54336568491f7086481e04f2875e60: 7/7 workflows.
GPS host run 45806815490 job 139864134611 confirmed six new
gconv parser tests, one real ext4 case and offline gate.

--plan-caches implies extended manifest and cache review, on
one verified snapshot. Bind all reports to image and closure
digests. Require exact staged ELF paths, hashes and aliases.
Separate missing paths, SONAME conflicts, duplicate records,
and HWCAP/OS version dependent entries. Old-only records have
unknown HWCAP and OS version, and are kept in review.
Record missing gconv modules and SONAMEs with no candidate
record. Candidates are review-only, not a cache specification.
Both original caches should remain excluded pending targeted
loader and gconv checks. No cache generation or installation.
Eight unit tests and one real ext4 case pending CI.
Original donor and actual runtime unavailable. safe_to_flash=false.
