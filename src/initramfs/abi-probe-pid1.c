/* SPDX-License-Identifier: GPL-2.0-only
 * QEMU virt diagnostic PID 1 only. Never package for a real watch.
 * Linked with abi-probe.c (main renamed to abi_probe_main).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#if defined(GALWEAR_BIONIC_PROBE)
#if !defined(__BIONIC__) || !defined(__ANDROID_API__) || __ANDROID_API__ != 30
#error "Bionic diagnostic requires Android API 30"
#endif
#endif

extern int abi_probe_main(void);
extern int binder_probe(void);

int main(void)
{
    if (getpid() != 1)
        return 2;
    if (setvbuf(stdout, NULL, _IONBF, 0))
        return 3;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    puts("r800-abi-pid1: guest PID=1");
#ifdef GALWEAR_BIONIC_PROBE
    puts("r800-libc: bionic api=30 static");
#endif
    int rc = abi_probe_main();
    if (rc != 0)
        return rc;
    if (binder_probe() != 0)
        return 4;
    puts("r800-abi-pid1: complete");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (nanosleep(&delay, NULL))
            continue;
        if (sequence == 0xffffffffU)
            continue;
        printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
