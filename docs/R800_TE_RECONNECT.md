# R800 TE source reconnection (NON-RELEASE)

Base: ce509d9414004af098fc9810d831bad699851917. Open the read-only TE sysfs node only while VSync is
enabled, retry at most once per two seconds after loss or open failure.
Retire the FD on HUP/NVAL or fatal poll error, or eight consecutive
malformed/duplicate notifications or POLLERR-only events. A timeout
with no TE is normal during display idle and does not cause reopen.
Rearm the baseline on reopen without sending a duplicate callback.
Keep timer VSync active during the retry interval; retain monotonic
last-sent timestamps. No panel reset, no new hardware interrupt writes.

Fix stale monotonic-condattr static test from lifecycle commit and
update VSync poll regression to follow the extracted helper.
Host C tests cover poll classification and retry deadline, not actual
sysfs behavior. Persistent lost kernel IRQ enable, callback unregister,
and real SurfaceFlinger restart remain open. Exact-head CI and NDK
compile required. safe_to_flash=false.
