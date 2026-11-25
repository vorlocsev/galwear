/* SPDX-License-Identifier: GPL-2.0-only
 * Generic virt read-only disk probe. No policy load or Android exec.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

static const char *const names[] = {"system", "system_ext", "product", "vendor", "odm", "runtime"};

static int allowed(const char *name)
{
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); ++i)
        if (!strcmp(name, names[i])) return 1;
    return 0;
}

static int serial_matches(const char *name, const char *device)
{
    char serial_path[128], serial[64];
    snprintf(serial_path, sizeof(serial_path), "/sys/block/%s/serial", device);
    int fd = open(serial_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, serial, sizeof(serial)-1);
    if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(serial)-1) return 0;
    if (serial[n-1] == '\n') --n;
    serial[n] = '\0';
    char expected[64];
    snprintf(expected, sizeof(expected), "galwear-%s", name);
    return strcmp(serial, expected) == 0;
}

static int mount_disk(const char *name)
{
    char device[] = "vda", candidate[] = "vda", target[128];
    unsigned matches = 0;
    for (char c = 'a'; c <= 'f'; ++c) {
        candidate[2] = c;
        if (serial_matches(name, candidate)) {
            device[2] = c;
            ++matches;
        }
    }
    if (matches != 1) return 3;
    char node[32];
    snprintf(node, sizeof(node), "/dev/%s", device);
    int fd = open(node, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 4;
    struct stat st;
    int ro = 0;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || ioctl(fd, BLKROGET, &ro) || ro != 1) {
        close(fd);
        return 5;
    }
    if (close(fd)) return 5;
    snprintf(target, sizeof(target), "/mnt/%s", name);
    if (mkdir(target, 0755) || mount(node, target, "ext4",
        MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "noload")) return 6;
    struct statfs fs;
    struct statvfs vfs;
    if (statfs(target, &fs) || (unsigned long)fs.f_type != 0xef53UL ||
        statvfs(target, &vfs) || !(vfs.f_flag & ST_RDONLY)) return 7;
    printf("r800-virt-disk: %s serial=PASS block-ro=1 ext4-ro=1\n", name);
    return 0;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) ||
        mkdir("/mnt", 0755)) return 2;
    FILE *list = fopen("/galwear-disks.list", "r");
    if (!list) return 3;
    char name[32], dev[16], line[80];
    unsigned count = 0;
    while (fgets(line, sizeof(line), list)) {
        char extra;
        if (!strchr(line, '\n') || sscanf(line, "%31s %15s %c", name, dev, &extra) != 2 ||
            !allowed(name) || count >= 6 ||
            strlen(dev) != 3 || dev[0] != 'v' || dev[1] != 'd' ||
            dev[2] != (char)('a' + count) || mount_disk(name))
            return 4;
        ++count;
    }
    if (ferror(list) || fclose(list) || !count) return 5;
    /* No unlisted device is mounted; images stay mounted read-only. */
    printf("r800-virt-disk: PASS count=%u policy=not-loaded android=not-started\n", count);
    const struct timespec delay = {5, 0};
    unsigned sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
