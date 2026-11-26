# Gconv declaration and module review

Baseline d696d335bf885fd35eb94f43eb13863ed9f1c0d2: 7/7 workflows.
GPS host run 45807548026 job 139866650863 confirmed eight cache
plan tests, real ext4 case and offline gate.

--review-gconv reads fixed /usr/lib/gconv/gconv-modules from
the same digest-verified snapshot. Single-link regular input
with nonsymlink directory parents. Strict ASCII alias/module
subset, bounded declarations, alias cycles and duplicate
conversions rejected. No arbitrary paths, includes, regex
matching or guest execution. Audit the baseline and declared
modules in the existing private ELF extraction directory,
require gconv function export, dependency/symbol/relocation
evidence. Missing or oversized module sets remain review.
Original extended manifest unaffected; no gconv staging,
cache generation, conversion selection, ABI or runtime claim.
Eight parser tests and two real ARM ELF/ext4 tests pending CI.
Original donor unavailable. safe_to_flash=false.
