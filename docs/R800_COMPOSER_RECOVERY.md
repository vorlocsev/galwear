# R800 SurfaceFlinger/composer recovery (NON-RELEASE)

Base: d907d661dbbc9eaea9d7ff379a7151d94583e280. Historical display watchdog escalated zero-copy stalls
to SysRq reboot and stopped the independent dead-man feeder. Remove
that escalation. Default is observation; an explicit developer marker
HWC_RESTART plus CPU-copy mode (debug.r800.zerocopy=0) authorizes one
experimental TERM attempt for the composer service per boot. Claim a
volatile /dev directory atomically before signaling and revalidate PID
start ticks and frame IRQ. Claim survives helper restart. Strip marker
from release packaging. No direct SurfaceFlinger kill, no forced reboot.
The independent hardware dead-man itself is unchanged.

TERM delivery is not proof of recovery. Init service coupling,
actual logcat PID/tag format, residual PID reuse race, DECON state and
first successful frame on real hardware remain unverified. Zero-copy
recovery deliberately remains diagnostic. No live tests, NDK build
or firmware flashing. safe_to_flash=false.
