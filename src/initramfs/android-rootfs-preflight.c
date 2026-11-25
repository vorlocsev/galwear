/* SPDX-License-Identifier: GPL-2.0-only
 * Generic virt rootfs preparation only. Never exec Android init.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

static int mounted(const char *path, unsigned long magic)
{
    struct statfs fs;
    return statfs(path, &fs) == 0 && (unsigned long)fs.f_type == magic;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0))
        return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        !mounted("/proc", 0x9fa0UL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        !mounted("/sys", 0x62656572UL) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) ||
        !mounted("/dev", 0x01021994UL) ||
        mount("tmpfs", "/data", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4m") ||
        !mounted("/data", 0x01021994UL))
        return 2;
    puts("r800-rootfs: proc=PASS sys=PASS dev=PASS data=PASS");
    if (mkdir("/dev/socket", 0755) ||
        access("/system/etc/selinux/plat_property_contexts", R_OK) ||
        access("/system/bin/galwear_property_client", X_OK) ||
        access("/system/bin/galwear_property_service", X_OK))
        return 3;
    struct stat st;
    if (stat("/dev/socket", &st) || !S_ISDIR(st.st_mode) ||
        (st.st_mode & 07777) != 0755 ||
        lstat("/dev/__properties__", &st) == 0 || errno != ENOENT ||
        lstat("/dev/socket/property_service", &st) == 0 || errno != ENOENT)
        return 4;
    puts("r800-rootfs: contexts-readable=PASS socket-directory=PASS");
    puts("r800-rootfs: PASS android-init=not-started policy=not-loaded");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
