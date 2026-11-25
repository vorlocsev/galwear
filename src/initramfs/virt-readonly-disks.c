/* SPDX-License-Identifier: GPL-2.0-only
 * Generic virt read-only disk probe. No policy load or Android exec.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/xattr.h>
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
#ifdef GALWEAR_LABEL_PROBE
    if (!strcmp(name, "runtime")) {
        if (mkdir("/apex", 0755)) return 6;
        snprintf(target, sizeof(target), "/apex/com.android.runtime");
    } else {
        snprintf(target, sizeof(target), "/%s", name);
    }
#else
    snprintf(target, sizeof(target), "/mnt/%s", name);
#endif
    if (mkdir(target, 0755) || mount(node, target, "ext4",
        MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "noload")) return 6;
    struct statfs fs;
    struct statvfs vfs;
    if (statfs(target, &fs) || (unsigned long)fs.f_type != 0xef53UL ||
        statvfs(target, &vfs) ||
        (vfs.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
        (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) return 7;
    printf("r800-virt-disk: %s serial=PASS block-ro=1 ext4-ro=1\n", name);
    return 0;
}

#ifdef GALWEAR_LABEL_PROBE
static unsigned char *read_blob(const char *path, size_t limit, size_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (unsigned long)st.st_size > limit)
        return NULL;
    *size = (size_t)st.st_size;
    unsigned char *buf = calloc(*size + 1, 1);
    if (!buf) return NULL;
    size_t offset = 0;
    while (offset < *size) {
        ssize_t n = read(fd, buf + offset, *size - offset);
        if (n <= 0) return NULL;
        offset += (size_t)n;
    }
    if (close(fd)) return NULL;
    return buf;
}

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

static int policy_and_labels(void)
{
    size_t policy_size, list_size;
    unsigned char *policy = read_blob("/galwear-policy", 16U*1024U*1024U, &policy_size);
    unsigned char *list = read_blob("/galwear-labels.list", 256U*1024U, &list_size);
    struct statfs fs;
    if (!policy || !list || memchr(list, '\0', list_size) || list[list_size-1] != '\n' ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        statfs("/sys/fs/selinux", &fs) || (unsigned long)fs.f_type != 0xf97cff8cUL ||
        !exact_text("/sys/fs/selinux/enforce", "1")) return 1;
    int fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 2;
    ssize_t n = write(fd, policy, policy_size);
    if (close(fd) || n != (ssize_t)policy_size) return 2;
    free(policy);
    if (!exact_text("/sys/fs/selinux/enforce", "1") ||
        !exact_text("/proc/self/attr/current", "u:r:kernel:s0")) return 3;
    puts("r800-disk-label: policy=PASS domain=u:r:kernel:s0 enforce=1");
    char *save = NULL;
    unsigned count = 0;
    for (char *line = strtok_r((char *)list, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char path[512], expected[256], actual[256], extra;
        if (sscanf(line, "%511s %255s %c", path, expected, &extra) != 2 ||
            path[0] != '/' || strstr(path, "..") || ++count > 1024)
            return 4;
        /* lgetxattr reads the effective kernel label without following a symlink.
         * Do not use setxattr, restorecon or change the enforcing state. */
        n = lgetxattr(path, "security.selinux", actual, sizeof(actual));
        if (n <= 0 || n >= (ssize_t)sizeof(actual)) return 5;
        if (actual[n-1] == '\0') --n;
        actual[n] = '\0';
        if (strcmp(actual, expected)) {
            fprintf(stderr, "r800-disk-label: FAIL path=%s actual=%s\n", path, actual);
            return 6;
        }
        printf("r800-disk-label: path=%s context=%s\n", path, actual);
    }
    free(list);
    if (!count || !exact_text("/sys/fs/selinux/enforce", "1") ||
        !exact_text("/proc/self/attr/current", "u:r:kernel:s0")) return 7;
    printf("r800-disk-label: PASS count=%u android=not-started\n", count);
    return 0;
}
#endif

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
#ifdef GALWEAR_LABEL_PROBE
    if (policy_and_labels()) return 6;
#endif
    const struct timespec delay = {5, 0};
    unsigned sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
}
