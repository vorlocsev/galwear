# ARM32 freestanding link blocker

Exact-head 692924cab5f2a566f87d7d7009d845f7cef004e8:
six workflows passed, GPS workflow 45769061918 failed in job
139737021817 during freestanding bridge link: undefined
__aeabi_ldivmod in aid. Ordinary ARM QEMU 18/18 passed.
The production source used signed 64-bit age / 60000 for the
cached fix log. The maximum permitted age is 30 days (2592000000
milliseconds), which fits unsigned 32 bits, but not signed 32 bits.

Change: validate the range before narrowing, calculate minutes and
accuracy using unsigned 32-bit arithmetic, retain the 30-day limit
and 1-day threshold. No libgcc/compiler-rt dependency is added.
Add ten assertions covering edge cases, a seed integration scenario,
and a compile-only check for undefined signed/unsigned long division
helpers for each XTRA variant. New exact-head CI pending.
Tizen donor link, QEMU donor and device runtime remain unverified.
safe_to_flash=false.
