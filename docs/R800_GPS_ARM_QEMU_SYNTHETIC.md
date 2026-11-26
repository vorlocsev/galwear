# ARM32 synthetic GPS bridge QEMU acceptance

Baseline 48668d2c7e3391b48c1a185743b6e05275c4dd83:
all seven workflows passed. Run 45768505685 confirmed 18 integration
tests, including actual daemon SIGKILL, SIGTERM and STOP during outage.

This new CI job compiles the actual bridge and synthetic Broadcom
library for ARMv7 EABI5 softfp with Ubuntu's arm-linux-gnueabi compiler.
It executes the bridge via qemu-arm with the distribution's ARM
glibc sysroot. Native HAL fixtures remain UBSan-instrumented. Both
bridge and mock must be ARM32 ELF, not x86. The same integration suite
is required in both modes. The ARM fixture deliberately uses the
host-test configuration with scratch-directory paths and system
headers; production freestanding compile-only checks remain separate.

The distribution glibc is NOT the original SM-R800 Tizen glibc 2.24.
No original firmware input or proprietary library is executed.
This job is not evidence of the production bridge's custom CRT,
vendor ABI or physical GNSS. The original donor-only QEMU probe
remains separate and blocked pending trusted donor files.
New QEMU job pending CI; no ARM runtime success asserted yet.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
