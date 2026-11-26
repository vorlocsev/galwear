# IPC v2 development-build default

On 2026-11-26, exact-head 6a7b353e8139a4707327dc28bffe7ec4c652b181
passed all six workflows. GPS run 45767924178, job 139733437653,
confirmed NDK r27c Android API28 ARM32 v1 and v2 shared-library links,
HMI export, ELF and dependency checks, distinct hashes and invalid
mode rejection. Host job 139733437424 confirmed full offline compile
gate, including all three ARM32 GPS Bridge XTRA compile-only variants.

This change selects v2 by default in gps_r800.c and r800_build_hals.sh.
Explicit R800_GPS_IPC_V2=0 retains v1 for a matched legacy bridge.
The current bridge supports both versions; older bridge binaries may
not understand HELLO 2. No automatic downgrade. Update both components
as a matched set only after device-specific acceptance.

Existing legacy fixture pins v1. New default-mode integration test
exercises the real source default and async mock. NDK gate additionally
compares the default artifact with explicitly built v2. These new
checks are pending CI at the time of this commit. No binary or firmware
published. Donor glibc link, real Broadcom, QEMU and hardware still
unverified. HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
