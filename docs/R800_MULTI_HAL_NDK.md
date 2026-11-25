# R800 multi-HAL NDK build (NON-RELEASE)

Base 80ad8167682ac176da8e7a62aa76577209a76beb: exact-head run 45535141486 passed; all four
original objects compiled, HWC linked, ARM DYN and HMI checked.
This change adds lights_r800.c and links GPS, sensors, lights and
HWC with NDK r27c / ARM32 / API 28. Each shared object must be ELF32
ARM DYN, export the HMI object, link with no undefined symbols at link
time, declare the correct SONAME and depend only on NDK libraries
libc/libm/libdl/liblog. Evidence JSON v3 includes dependencies and hashes.

Audio remains compile-only because the hardware-specific tinyalsa
sync_ptr patch has not been located. No stock-library replacement.
No donor image, Android linker namespace or HAL runtime validation.
No binaries are uploaded; only metadata. New exact-head CI pending.
safe_to_flash=false.
