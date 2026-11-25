/* SPDX-License-Identifier: Apache-2.0
 * Stock-policy rootfs labeling diagnostic. No exec, no policy relaxation.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static unsigned char *read_blob(const char *path, size_t cap, size_t *size)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (unsigned long)st.st_size > cap)
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

static int domain_is_kernel(void)
{
    char *context = NULL;
    if (getcon(&context) < 0) return 0;
    int ok = !strcmp(context, "u:r:kernel:s0");
    freecon(context);
    return ok;
}

static int relabel(struct selabel_handle *handle, const char *path)
{
    struct stat st;
    char *expected = NULL, *actual = NULL;
    if (lstat(path, &st) ||
        selabel_lookup(handle, &expected, path, st.st_mode) ||
        selinux_android_restorecon(path, 0) ||
        lgetfilecon(path, &actual) < 0)
        return 1;
    int match = !strcmp(expected, actual);
    if (match)
        printf("r800-relabel: path=%s context=%s\n", path, actual);
    freecon(expected);
    freecon(actual);
    return !match;
}

int main(void)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0)) return 1;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    size_t policy_len, list_len;
    unsigned char *policy = read_blob("/galwear-policy", 16U*1024U*1024U, &policy_len);
    unsigned char *list = read_blob("/galwear-relabel.list", 65536, &list_len);
    if (!policy || !list || memchr(list, '\0', list_len) || list[list_len-1] != '\n')
        return 2;
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) ||
        mount("tmpfs", "/data", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4m") ||
        mkdir("/dev/socket", 0755))
        return 3;
    set_selinuxmnt("/sys/fs/selinux");
    if (security_getenforce() != 1) return 4;
    int fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 5;
    ssize_t n = write(fd, policy, policy_len);
    if (close(fd) || n != (ssize_t)policy_len ||
        security_getenforce() != 1 || !domain_is_kernel())
        return 6;
    free(policy);
#ifdef GALWEAR_SERVICE_BOOT
    puts("r800-relabel: fixture-policy=PASS enforce=1");
#else
    puts("r800-relabel: stock-policy=PASS enforce=1");
#endif
    struct selabel_handle *handle = selinux_android_file_context_handle();
    if (!handle) return 7;
    char *save = NULL;
    unsigned count = 0;
    for (char *path = strtok_r((char *)list, "\n", &save); path;
         path = strtok_r(NULL, "\n", &save)) {
        if (path[0] != '/' || strstr(path, "..") || ++count > 512 ||
            relabel(handle, path)) {
            fprintf(stderr, "r800-relabel: FAIL path=%s\n", path);
            return 8;
        }
    }
    selabel_close(handle);
    free(list);
    if (!count || security_getenforce() != 1 || !domain_is_kernel()) return 9;
#ifdef GALWEAR_SERVICE_BOOT
    printf("r800-relabel: PASS count=%u service=handover\n", count);
    char path[] = "/system/bin/galwear_property_service";
    char stage[] = "--virt-property-service";
    char *const args[] = {path, stage, NULL};
    char *const env[] = {NULL};
    execve(path, args, env);
    return 10;
#else
    printf("r800-relabel: PASS count=%u service=not-started\n", count);
    const struct timespec delay = {5, 0};
    unsigned int sequence = 0;
    for (;;) {
        if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
            printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
    }
#endif
}
