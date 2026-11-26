# Freestanding ARM32 GPS bridge synthetic runtime gate

Baseline 050bbbd52667526ea143623391c9988cc90d7eb0:
seven workflows passed; run 45768809079 job 139736181033 reported
18/18 ARM32 QEMU integration tests and GPS_ARM32_SYNTHETIC_QEMU=PASS.
The baseline bridge used host-test libc headers and normal CRT.

New test mode 2 compiles the production freestanding branch with
Clang, own _start and hand-declared glibc functions, including the
ARM ABI static assertions, raw statx syscall and static mutex storage.
A fixture-only macro substitutes scratch socket, seed and mock library
paths. Peer credentials are the non-root runner UID/GID. The ARM GNU
linker uses the distribution ARM glibc, without CRT startup objects or
implicit standard libraries. The same 18-test suite is required.
No device or firmware artifact is produced. This check is pending CI.

Ubuntu ARM glibc is not Tizen 2.24, and the synthetic callback table
is not the proprietary Broadcom ABI. Original donor link and isolated
donor QEMU checks remain blocked pending trusted local Tizen files.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
