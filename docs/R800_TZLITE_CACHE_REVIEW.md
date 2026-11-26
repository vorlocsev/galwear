# Static loader and gconv cache review

Baseline bdb76de0b0b9557c1a3ce0464d924d5c1a4c0370: 7/7 workflows.
GPS host run 45802342831 job 139848530866 confirmed seven NSS
unit tests and two real ELF cases.

Opt-in --review-caches on legacy image scope, implies plugin
audit. Bind exact regular cache files to inventory hashes.
Recognize little-endian glibc 2.24 old, new and compatible
loader cache tables; use new table in compatible format.
Inventory gconv primary tables and referenced module paths.
Bound counts, offsets and strings. Compare exact cache paths
against canonical files and aliases in audited ELF subset.
Do not resolve arbitrary cache paths, copy caches or execute
ldconfig/iconvconfig. Legacy compatibility table in combined
format, loader flags/HWCAP selection, gconv hash lookup and
extra conversion chains not verified. No claim of complete
cache validity or runtime compatibility.
Reference: https://github.com/bminor/glibc/tree/glibc-2.24
(sysdeps/generic/dl-cache.h, elf/dl-cache.c,
iconv/iconvconfig.h, iconv/iconvconfig.c, iconv/gconv_cache.c).
Eight unit tests and one real ext4 fixture pending CI.
Original donor unavailable. safe_to_flash=false.

## Exact-path fixture correction

CI 2f820461f51611ae4619167a787dd211a85ba9bf: 4/7 workflows.
Host run 45804413734 job 139855741305 failed only
`test_cache_review_real_image`: fixture referenced donor alias
/usr/lib/libfixture.so.1, while dependency audit selects the
/lib/libfixture.so.1 alias (canonical /usr/lib/libfixture-real.so).
Android HAL and synthetic ARM QEMU jobs succeeded. Correct positive
fixture to use the audited alias and add separate real ext4
negative test proving the donor-only alias stays outside the
staged subset. No production classifier relaxation. CI pending.

## Gconv fixture correction

CI d389ac5dd84c9c56a53ec29cf47214d7da07dd72: four successful
workflows, two failures, one workflow not returned at review.
Host run 45805238803 job 139858618044 failed the gconv part
of test_cache_review_real_image; exact-path negative case passed.
The fixture encoded module string offset 25 (NUL terminator of
/usr/lib/gconv/) rather than 26 (start of UTF-16.so).
Calculate offsets from appended strings, explicitly reject empty
module name, validate fixture before building ext4 and run cache
unit tests before real ELF tests. No production parser relaxation.
Android HAL and synthetic ARM QEMU jobs passed. New CI pending.
