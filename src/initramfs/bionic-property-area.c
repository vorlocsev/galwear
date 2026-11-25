/* SPDX-License-Identifier: GPL-2.0-only
 * Source-built Android 11 Bionic diagnostic, not Android init or property service.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "property_fixture.h"

#ifndef __BIONIC__
#error "Requires source-built Bionic"
#endif

/* Private Android 11 Bionic interfaces, used by AOSP init. */
extern int __system_property_area_init(void);
extern int __system_property_add(const char *, unsigned int, const char *, unsigned int);
extern int __system_property_update(prop_info *, const char *, unsigned int);

static const char name[] = "debug.galwear.probe";

struct reading {
    const char *expected;
    uint32_t serial;
    int matches;
    unsigned int count;
};

static void callback(void *cookie, const char *key, const char *value, uint32_t serial)
{
    struct reading *r = cookie;
    r->count++;
    r->matches = !strcmp(key, name) && !strcmp(value, r->expected);
    r->serial = serial;
}

static int check(const prop_info *pi, const char *expected, uint32_t *serial)
{
    struct reading r = {.expected = expected};
    if (!pi) return 1;
    __system_property_read_callback(pi, callback, &r);
    *serial = r.serial;
    return r.count != 1 || !r.matches;
}

static int write_blob(const char *path, const unsigned char *blob, size_t len, int flags)
{
    int fd = open(path, flags | O_WRONLY | O_CLOEXEC, 0444);
    if (fd < 0) return 1;
    ssize_t n = write(fd, blob, len);
    return close(fd) || n != (ssize_t)len;
}

static int reader(int notify)
{
    const prop_info *pi = __system_property_find(name);
    uint32_t first, changed, last;
    const struct timespec timeout = {5, 0};
    if (getpid() == 1 || getppid() != 1 || check(pi, "ready", &first))
        return 10;
    puts("r800-property-area: separate-exec read=ready");
    if (write(notify, "R", 1) != 1 || close(notify))
        return 11;
    if (!__system_property_wait(pi, first, &changed, &timeout) ||
        changed == first || check(pi, "updated", &last) || last != changed)
        return 12;
    puts("r800-property-area: wait=PASS updated-read=PASS serial-changed=PASS");
    return 0;
}

int main(int argc, char **argv)
{
    if (setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    if (argc == 3 && !strcmp(argv[1], "--reader")) {
        char *end;
        long n = strtol(argv[2], &end, 10);
        if (*end || n < 3 || n > 1024) return 1;
        return reader((int)n);
    }
    if (argc != 1 || getpid() != 1) return 2;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        write_blob("/sys/fs/selinux/load", policy_blob, sizeof(policy_blob), 0) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) ||
        mkdir("/dev/__properties__", 0711) ||
        write_blob("/dev/__properties__/property_info", property_info_blob,
                   sizeof(property_info_blob), O_CREAT | O_EXCL) ||
        __system_property_area_init() != 0)
        return 3;
    if (__system_property_find(name) ||
        __system_property_add(name, sizeof(name) - 1, "ready", 5) != 0)
        return 4;
    const prop_info *pi = __system_property_find(name);
    uint32_t serial;
    if (check(pi, "ready", &serial)) return 5;
    puts("r800-property-area: init=PASS add=PASS");
    int signal_pipe[2];
    if (pipe(signal_pipe)) return 6;
    pid_t child = fork();
    if (child < 0) return 7;
    if (!child) {
        char fd[16];
        close(signal_pipe[0]);
        snprintf(fd, sizeof(fd), "%d", signal_pipe[1]);
        char *const args[] = {"/init", "--reader", fd, NULL};
        char *const env[] = {NULL};
        execve("/init", args, env);
        _exit(127);
    }
    close(signal_pipe[1]);
    char ready;
    if (read(signal_pipe[0], &ready, 1) != 1 || ready != 'R' ||
        close(signal_pipe[0]) ||
        __system_property_update((prop_info *)pi, "updated", 7) != 0)
        return 8;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        return 9;
    puts("r800-property-area: PASS service=not-started");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
