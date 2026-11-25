/* SPDX-License-Identifier: GPL-2.0-only
 * Dedicated QEMU virt dynamic Android diagnostic PID1. No storage devices.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0))
        return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
        return 2;
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL))
        return 3;
    char *const argv[] = {"/system/bin/galwear-dynamic-probe", NULL};
    char *const envp[] = {"PATH=/system/bin", "ANDROID_ROOT=/system",
                          "ANDROID_DATA=/data", NULL};
    pid_t child = fork();
    if (child < 0)
        return 4;
    if (child == 0) {
        execve(argv[0], argv, envp);
        perror("dynamic execve");
        _exit(127);
    }
    int status;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 5;
    if (umount("/dev") || umount("/proc"))
        return 6;
    puts("r800-dynamic-pid1: child-exit=0");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
