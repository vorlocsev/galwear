/* SPDX-License-Identifier: GPL-2.0-only
 * Stock Android policy load diagnostic for disposable generic virt only.
 * No setenforce, setcon, exec or Android init transition.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#define MAX_POLICY (16U * 1024U * 1024U)

static int enforcing(void)
{
    char buf[8];
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf));
    return close(fd) == 0 && n == 1 && buf[0] == '1';
}

static int read_policy(void **blob, size_t *size)
{
    int fd = open("/galwear-policy", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 32 || st.st_size > MAX_POLICY)
        return 1;
    *size = (size_t)st.st_size;
    *blob = malloc(*size);
    if (!*blob) return 1;
    size_t offset = 0;
    while (offset < *size) {
        ssize_t n = read(fd, (char *)*blob + offset, *size - offset);
        if (n <= 0) return 1;
        offset += (size_t)n;
    }
    return close(fd) != 0;
}

static int report_domain(void)
{
    char buf[256];
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(buf)-1) return 1;
    if (buf[n-1] == '\0' || buf[n-1] == '\n') --n;
    buf[n] = '\0';
    /* Initial kernel SID maps to kernel domain, not Android init. */
    if (strcmp(buf, "u:r:kernel:s0") != 0) {
        fprintf(stderr, "r800-stock-policy: unexpected-domain=%s\n", buf);
        return 1;
    }
    puts("r800-stock-policy: current-domain=u:r:kernel:s0");
    return 0;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    struct statfs fs;
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        statfs("/sys/fs/selinux", &fs) || (unsigned long)fs.f_type != 0xf97cff8cUL ||
        !enforcing())
        return 2;
    void *blob = NULL;
    size_t size = 0;
    if (read_policy(&blob, &size)) return 3;
    int fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 4;
    ssize_t n = write(fd, blob, size);
    if (close(fd) || n != (ssize_t)size) return 5;
    free(blob);
    if (!enforcing()) return 6;
    puts("r800-stock-policy: load=PASS enforce=1");
    if (report_domain()) return 7;
    puts("r800-stock-policy: PASS android-init=not-started relabel=not-tested");
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
