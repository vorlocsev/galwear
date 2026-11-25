/* SPDX-License-Identifier: Apache-2.0
 * AOSP-linked diagnostic for a disposable virt guest only.
 * The /system/bin/init path contains THIS diagnostic, not stock init.
 */
#include <errno.h>
#include <fcntl.h>
#include <selinux/android.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#define MAX_POLICY (16U * 1024U * 1024U)
#define TARGET "/system/bin/init"

static int context_is(const char *expected)
{
    char *context = NULL;
    if (getcon(&context) < 0) return 0;
    int match = strcmp(context, expected) == 0;
    freecon(context);
    return match;
}

static int load_stock_policy(void)
{
    int fd = open("/galwear-policy", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 32 || st.st_size > MAX_POLICY)
        return 1;
    size_t size = (size_t)st.st_size, offset = 0;
    unsigned char *data = malloc(size);
    if (!data) return 1;
    while (offset < size) {
        ssize_t n = read(fd, data + offset, size - offset);
        if (n <= 0) return 1;
        offset += (size_t)n;
    }
    if (close(fd)) return 1;
    fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    ssize_t n = write(fd, data, size);
    free(data);
    return close(fd) || n != (ssize_t)size;
}

int main(int argc, char **argv)
{
    if (getpid() != 1 || setvbuf(stdout, NULL, _IONBF, 0))
        return 1;
    if (argc == 2 && strcmp(argv[1], "--diagnostic-second-stage") == 0) {
        if (!context_is("u:r:init:s0") || security_getenforce() != 1)
            return 2;
        puts("r800-transition: domain=u:r:init:s0 enforce=1");
        puts("r800-transition: PASS diagnostic-only stock-init=not-started");
        const struct timespec delay = {5, 0};
        unsigned int sequence = 0;
        for (;;) {
            if (!nanosleep(&delay, NULL) && sequence != 0xffffffffU)
                printf("r800-readonly-init: heartbeat %08x\n", ++sequence);
        }
    }
    if (argc != 1) return 3;
    puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    struct statfs fs;
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        statfs("/sys/fs/selinux", &fs) || (unsigned long)fs.f_type != 0xf97cff8cUL)
        return 4;
    /* Static libselinux constructors may have run before selinuxfs existed. */
    set_selinuxmnt("/sys/fs/selinux");
    if (security_getenforce() != 1 || load_stock_policy() ||
        security_getenforce() != 1 || !context_is("u:r:kernel:s0"))
        return 4;
    puts("r800-transition: stock-policy=PASS domain=u:r:kernel:s0");
    if (selinux_android_restorecon(TARGET, 0) != 0)
        return 5;
    char *label = NULL;
    if (lgetfilecon(TARGET, &label) < 0)
        return 6;
    int match = strcmp(label, "u:object_r:init_exec:s0") == 0;
    freecon(label);
    if (!match) return 7;
    puts("r800-transition: restorecon=PASS label=u:object_r:init_exec:s0");
    char path[] = TARGET;
    char stage[] = "--diagnostic-second-stage";
    char *const args[] = {path, stage, NULL};
    char *const env[] = {NULL};
    execve(path, args, env);
    return 8;
}
