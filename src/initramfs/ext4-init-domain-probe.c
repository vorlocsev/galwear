/* SPDX-License-Identifier: GPL-2.0-only
 * Static second-stage diagnostic ONLY, deliberately not Android init.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int exact_text(const char *path, const char *expected)
{
    char buf[256];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(buf)-1) return 0;
    if (buf[n-1] == '\0' || buf[n-1] == '\n') --n;
    buf[n] = '\0';
    return !strcmp(buf, expected);
}

int main(int argc, char **argv)
{
    if (getpid() != 1 || argc != 2 ||
        strcmp(argv[1], "--galwear-ext4-diagnostic") ||
        setvbuf(stdout, NULL, _IONBF, 0))
        return 1;
    if (!exact_text("/proc/self/attr/current", "u:r:init:s0") ||
        !exact_text("/sys/fs/selinux/enforce", "1"))
        return 2;
    char exe[256], label[256];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (n <= 0 || n >= (ssize_t)sizeof(exe)-1) return 3;
    exe[n] = '\0';
    if (strcmp(exe, "/system/bin/init")) return 3;
    n = lgetxattr(exe, "security.selinux", label, sizeof(label)-1);
    if (n <= 0 || n >= (ssize_t)sizeof(label)-1) return 4;
    if (label[n-1] == '\0') --n;
    label[n] = '\0';
    if (strcmp(label, "u:object_r:init_exec:s0")) return 4;
    struct statvfs fs;
    if (statvfs("/system", &fs) ||
        (fs.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
        (ST_RDONLY | ST_NOSUID | ST_NODEV)) return 5;
    struct stat console_stat;
    if (fstat(STDOUT_FILENO, &console_stat) == 0 && S_ISCHR(console_stat.st_mode)) {
        printf("r800-console: stage=init device=%u:%u inode=%llu filesystem=%u:%u\n",
               (unsigned)major(console_stat.st_rdev), (unsigned)minor(console_stat.st_rdev),
               (unsigned long long)console_stat.st_ino,
               (unsigned)major(console_stat.st_dev), (unsigned)minor(console_stat.st_dev));
        fflush(stdout);
    } else {
        fputs("r800-console: stage=init descriptor-unavailable\n", stderr);
        fflush(stderr);
    }
    puts("r800-ext4-transition: domain=u:r:init:s0 enforce=1 pid=1");
    puts("r800-ext4-transition: executable=/system/bin/init label=u:object_r:init_exec:s0");
    puts("r800-ext4-transition: PASS diagnostic-only stock-init=not-started");
    const struct timespec delay = {5, 0};
    unsigned sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
