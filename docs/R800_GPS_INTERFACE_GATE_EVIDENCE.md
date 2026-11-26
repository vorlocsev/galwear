# GPS interface table gate evidence

Tested source reference: 19e7e061246d1ee2b3f576bf0fa68ac2cbfde827.
Three files were reproduced locally and git hash-object matched GitHub:

- 84b20b6911ce3978e7c6640f481a4b4b770ecd7a src/tools/gps/gps_interface_gate.h
- 4fd5f7d01e942711549daa23d8cd63995f549dda src/tools/gps/gps_abi.h
- 752b3f776fe6240854c0739bea506161bac0db1d tests/test_r800_gps_interface.c

Executed native Linux GCC 14.2 with -std=gnu11 -O2 -Wall -Wextra -Werror
-UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all and each
R800_XTRA_ABI=0,1,2. All three executables returned zero and emitted
GPS_INTERFACE_GATE=PASS. Includes a size-only table ending just before
a PROT_NONE page, missing required slots, misalignment and size mismatch.

A temporary freestanding translation unit included the exact two headers
and invoked both validators. Clang 17 compiled it for
armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16
in all three XTRA modes; readelf showed ELF32, ARM, EABI5 (0x5000000).
This is compile-only, not execution or target linking.

The bridge now requires an exact local table size before reading
function slots, rather than accepting unknown larger layouts. This is
a deliberate conservative compatibility choice and can reject an otherwise
compatible extended vendor table. Checks assume a readable live pointer;
they cannot establish pointer mapping, lifetime, executable addresses,
function signatures, or actual Broadcom ABI. XTRA defaults to disabled.

No complete checkout, full bridge compile, integration test, CI, donor
execution, QEMU or device test was performed in this step. Previous
test reports were not independently rerun.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
