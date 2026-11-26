# External gconv reference consistency

Baseline fc0558f185ea22c9e3a0a3f8db0ed9b54c9c15b1: 7/7 workflows.
GPS host run 45808231703 job 139868995432 confirms eight parser
and two real ARM ELF/ext4 tests.

--compare-gconv implies cache and gconv reviews in one snapshot.
Record directed external module references in primary and extra
cache tables. Normalize ASCII names and declared aliases. Compare
source/destination/module triples and bind module records to the
audited ELF closure. Report unmatched edges and unresolved modules.
This is strict set equality, not glibc path selection, cost
optimization, builtin conversion or hash lookup verification.
Text-only declarations may legitimately be omitted by iconvconfig;
they remain review items, not proven runtime failures. The real
ext4 test uses a synthetic edge, not a functioning converter.
Seven unit tests and one real ext4 case pending CI. No staging
or generation authorized. No changes to existing extended manifest.
safe_to_flash=false.
