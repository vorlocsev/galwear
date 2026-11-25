# R800 HWC callback lifetime (NON-RELEASE)

Base: 3fc7d66701358a766885443cda79eab1d21f6e23. VSync previously borrowed a callback pointer under lock,
then used it after releasing the lock. Re-registration could return while
the old pointer was still in use. Dispatch now pins the registration;
replacement waits for outstanding dispatch and blocks new pins until
publication. Every replacement increments the epoch. NULL unregisters.
Framework callbacks execute outside the HAL mutex. The vendored HWC1
header explicitly guarantees VSync does not reenter HAL hooks.

Host regression exercises real pthread replacement in 100 cycles.
Limits: callers must retain callback storage until unregister/replacement
returns; contract-violating reentrant replacement requires storage to
outlive the current callback. Concurrent close with external entrypoints
is not supported. No guarantee against framework lock inversion or
a permanently blocked callback. Full NDK build and hardware restart
still unverified. safe_to_flash=false.
