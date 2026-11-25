/* SPDX-License-Identifier: GPL-2.0-only
 *
 * SM-R800 NON-RELEASE minimal AArch64 /init for offline compile smoke testing.
 *
 * No filesystem mounts, block device access, framebuffer writes, persistent
 * logging, power management changes or handover to the historical /data
 * startup. Only writes a startup marker and numbered heartbeat messages to
 * the kernel-provided stdout, sleeping between heartbeats. NOT a functional Wear OS or hardware boot guarantee.
 */
typedef unsigned long u64;
typedef long s64;

struct tiny_timespec {
    s64 seconds;
    s64 nanoseconds;
};

/* Linux AArch64 syscall #64, output only to already-open stdout. */
static s64 console_write(const char *buffer, u64 bytes)
{
    register s64 x0 asm("x0") = 1;
    register s64 x1 asm("x1") = (s64)buffer;
    register s64 x2 asm("x2") = (s64)bytes;
    register s64 x8 asm("x8") = 64;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x8)
                 : "memory");
    return x0;
}

/* Linux AArch64 syscall #101, idle without busy-looping. */
static s64 idle_sleep(const struct tiny_timespec *interval)
{
    register s64 x0 asm("x0") = (s64)interval;
    register s64 x1 asm("x1") = 0;
    register s64 x8 asm("x8") = 101;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x8)
                 : "memory");
    return x0;
}

__attribute__((noreturn))
void _start(void)
{
    static const char message[] =
        "r800-readonly-init: NON-RELEASE smoke image; "
        "no eMMC mount, no Wear OS handover\n";
    const struct tiny_timespec interval = {5, 0};
    static const char hex[] = "0123456789abcdef";
    char heartbeat[] = "r800-readonly-init: heartbeat 00000000\n";
    unsigned int sequence = 0;

    (void)console_write(message, sizeof(message) - 1);
    for (;;) {
        if (idle_sleep(&interval) != 0)
            continue;
        if (sequence == 0xffffffffU)
            continue;
        ++sequence;
        for (unsigned int i = 0; i < 8; ++i)
            heartbeat[sizeof(heartbeat) - 10 + i] = hex[(sequence >> (28 - 4 * i)) & 15U];
        (void)console_write(heartbeat, sizeof(heartbeat) - 1);
    }
}
