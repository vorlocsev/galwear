# R800 Android NDK compile and HWC link gate (NON-RELEASE)

Base: 55c1e63e6789cc3d376dacfd318c10f839c3319d. Previous integration run 45497778991 failed before
compilation because sdkmanager was absent (exit 127). Use Google's
official r27c Linux archive, verify published SHA-1
090e8083a715fdb1a3e402d0763c388abb03fb4e and exact NDK revision.
Reference: https://github.com/android/ndk/wiki/Home/b35b56c5c58c37771c404832c565f0ca4ee5aaab

Enable the existing integrated HAL workflow on the active display branch.
Compile audio/GNSS/sensors/HWC ARM32 API 28 with pinned tinyalsa headers.
Link HWC with NDK libraries and no unresolved link-time symbols; verify
ELF ARM DYN and exported HMI. Upload JSON evidence only.
Fix missing comparison argument in watchdog regression.

No binaries published, no donor images, no full audio/GNSS/sensors linking,
no VNDK runtime or HWC2On1 compatibility proof, no physical boot.
Compilation/link results are pending exact-head CI. safe_to_flash=false.
